#! /usr/bin/env ./osbwlst.sh

# OSB Services Tool

# Autores:
# Daniel Peñaloza
# Alfredo Peña
# Eduardo Sara

# Cambios:
# Version 1.1:
#   - Todos los archivos se leen y escriben en utf-8. Eso permite no perder acentos en los campos (especialmente los de politicas de seguridad)
#   - Agregado un modo de actualizacion de todos los tipos de componentes al mismo tiempo
#   - Solucionado el problema de actualizacion de las politicas de seguridad
#   - Los campos boolean (SI/NO) pueden estar en minusculas en el archivo
#   - Los headers de los archivos se graban como comentarios (empezando con #) para evitar leerlos al procesar el archivo
# Version 1.2:
#   - Agregado verificacion Bug 29469271 - Issue with Services After Importing Projects From 11g to 12c 
#   - Un poco de refactoring
# Falta:
#   - Verificar el cumplimento de las reglas de seguridad informatica en las politicas de seguridad
#   - Agregar el modo de insercion de un usuario nuevo a un proxy en particular sin necesidad de ir por la modificacion del csv
#   - Mejorar el manejo de workmanagers en otros protocolos, como MQ donde los proxys tienen 2 tipos de workmanager
#   - Crear comentarios en el commit mas descriptivos de los cambios realizados
#   - Poder eliminar la politica de seguridad de un proxy
#   - Verificar que el protocolo de los servicios continue siendo el mismo en el servidor y en el reporte para evitar confusiones
#   - Agregar capacidad de mandar reporte resumido por mail/consola de cantidad de pipelines en debug, etc 

# Uso:
# osbwlst.sh osb_services_tool.py
# Use: osb_services_tool.py [OPTIONS]
# List/Updates the configuration of proxies, business and pipelines of the osb domain.
# Example: osb_services_tool.py -o list -s 192.168.1.10 -l 7010 -u usradm -p secret
# Example: osb_services_tool.py --operation list --server 192.168.1.10 --listen_port 7010 --user_name usradm --password secret
# OPTIONS:
#   -v --verbose
#   -o --operation       list/updateps/updatebs/updatepipe/updateall
#   -s --server          Server to connect
#   -l --listen_address  Listen adress
#   -u --user_name       User name
#   -p --password        Password
#   -f --rep_proxy       filenameProxies.csv
#   -b --rep_business    filenameBusiness.csv
#   -n --rep_pipelines   filenamePipelines.csv
#   -c --comment         Comment in commits


from java.util import HashMap, HashSet
from java.lang.management import ManagementFactory
from javax.management import MBeanServerConnection, ObjectName
from javax.management.remote import JMXConnectorFactory, JMXServiceURL
from javax.naming import Context

from weblogic.management.jmx import MBeanServerInvocationHandler
from weblogic.management.mbeanservers.domainruntime import DomainRuntimeServiceMBean
from com.bea.wli.config import Ref
from com.bea.wli.sb.management.configuration import ALSBConfigurationMBean, ServiceConfigurationMBean, PipelineConfigurationMBean, OperationalSettingsQuery, ServiceSecurityConfigurationMBean, SessionManagementMBean
from com.bea.wli.sb.services import ProxyServiceEntryDocument
from com.oracle.xmlns.servicebus.business.config import BusinessServiceEntryDocument
from com.bea.wli.sb.services.operations import LogSeverityLevel
from com.bea.wli.sb.resources.pipeline.operations import PipelineOperationsBean
from com.bea.wli.sb.resources.service.operations import ProxyOperationsBean, BusinessOperationsBean, MessageTracingLevel
from com.bea.wli.sb.transports.http import HttpUtil
from com.bea.wli.sb.transports.sb import SBTransportUtils
from com.bea.wli.sb.transports.mq import MQTransportUtil
from com.bea.wli.sb.transports.tuxedo import TuxedoUtil
from com.bea.wli.sb.transports.jca import JCATransportUtils
from com.bea.wli.sb.transports.jms import JmsUtil
import codecs
import re

# Configuracion
file_reporte_proxys = 'reporteProxyServices.csv'
file_reporte_business = 'reporteBusinessServices.csv'
file_reporte_pipelines = 'reportePipelines.csv'
mods_per_session = 10
session_name = 'osbwlst_'+sys.argv[0]
commit_comment = ''

# Variables Globales
proxys, business, pipelines = {}, {}, {}
pipelinesEnDebug = 0
businessFullTrace, businessHeadersTrace, connTimeOut, readTimeOut, wmDefault = 0, 0, 0, 0, 0
proxyFullTrace, proxyHeadersTrace = 0, 0
verbose = False

alsb_core, service_conf_mbean, service_security_conf_mbean, xacmlauth, default_auth, pipeline_conf_mbean, session_mgmt_mbean = '','','','','','',''

def get_mbean_server_connection(hostname, port, username, password):
    if verbose:
        print "Conectandome al servidor de jmx..."
    jmx_service_url = JMXServiceURL("t3", hostname, port, "/jndi/%s"%DomainRuntimeServiceMBean.MBEANSERVER_JNDI_NAME)
    credentials_map = HashMap()
    credentials_map.put(Context.SECURITY_PRINCIPAL, username)
    credentials_map.put(Context.SECURITY_CREDENTIALS, password)
    credentials_map.put(JMXConnectorFactory.PROTOCOL_PROVIDER_PACKAGES, "weblogic.management.remote")
    return  JMXConnectorFactory.connect(jmx_service_url, credentials_map)

def close_connection(conn, for_update):
    if verbose:
        print "Cerrando la conexion jmx..."
    if for_update:
        discard_session()
    conn.close()

def get_conf_mbean(conn, mbean_class, sessionId):
    conf_name = ObjectName("com.bea:Name=" + mbean_class.NAME + sessionId  + ",Type=" + mbean_class.TYPE)
    mbeans = HashSet()
    mbeans.addAll( conn.queryNames(conf_name, None) )
    return  MBeanServerInvocationHandler.newProxyInstance(conn, mbeans.iterator().next(), mbean_class, false)

def set_security_policy(ref, policy):
    if policy != 'None':
        policyHolder = service_security_conf_mbean.newAccessControlPolicyHolderInstance("XACMLAuthorizer")
        policyHolder.setPolicyExpression(policy)
        policyScope = service_security_conf_mbean.newTransportPolicyScope(ref)
        service_security_conf_mbean.setAccessControlPolicy(policyScope,policyHolder)
        return True
    return False

def get_servicebus_mbeans(conn, for_update):
    global domain_service, alsb_core, service_conf_mbean, session_mgmt_mbean
    global service_security_conf_mbean, xacmlauth, default_auth, pipeline_conf_mbean
    
    domain_service = MBeanServerInvocationHandler.newProxyInstance(conn, ObjectName(DomainRuntimeServiceMBean.OBJECT_NAME))
    sec_config = domain_service.getDomainConfiguration().getSecurityConfiguration()
    default_auth = sec_config.getDefaultRealm().lookupAuthenticationProvider('DefaultAuthenticator')
    session_mgmt_mbean = domain_service.findService(SessionManagementMBean.NAME, SessionManagementMBean.TYPE, None)
    if for_update:
        session_id = '.' + session_name
        create_session()
    else:
        session_id = ''
    alsb_core = get_conf_mbean(conn, ALSBConfigurationMBean, session_id)
    service_conf_mbean = get_conf_mbean(conn, ServiceConfigurationMBean, session_id)
    pipeline_conf_mbean = get_conf_mbean(conn, PipelineConfigurationMBean, session_id)
    
    service_security_conf_mbean = get_conf_mbean(conn, ServiceSecurityConfigurationMBean, session_id)
    xacmlauth = service_security_conf_mbean.newAuthorizationProviderIdentifier("XACMLAuthorizer")

def connect_to_jmx(server, listen_port, user_name, password, for_update):
    connector = get_mbean_server_connection(server, int(listen_port), user_name, password)
    conn = connector.getMBeanServerConnection()
    get_servicebus_mbeans(conn,for_update)
    return connector

def discard_session():
    if session_mgmt_mbean.sessionExists(session_name):
        session_mgmt_mbean.discardSession(session_name)

def activate_session(comment):
    if session_mgmt_mbean.sessionExists(session_name):
        session_mgmt_mbean.activateSession(session_name, comment)

def create_session():
    discard_session()
    session_mgmt_mbean.createSession(session_name)

def get_provider_specific(protocolo, endpoint_conf):
    provider_specific = ''
    # Solo evaluo los protocolos que tienen WM (http, sb, mq, tuxedo)
    if protocolo == "http":
        provider_specific = HttpUtil.getHttpConfig(endpoint_conf)
    if protocolo == "sb":
        provider_specific = SBTransportUtils.getConfig(endpoint_conf)
    if protocolo == "mq":
        provider_specific = MQTransportUtil.getMQConfig(endpoint_conf)
    if protocolo == "tuxedo":
        provider_specific = TuxedoUtil.getTuxedoConfig(endpoint_conf)
    if protocolo == "jca":
        provider_specific = JCATransportUtils.getConfig(endpoint_conf)
    if protocolo == "jms":
        provider_specific = JmsUtil.getJmsConfig(endpoint_conf)
    return provider_specific
    
def get_workmanager(protocolo, endpoint_conf):
    global wmDefault
    workManager = 'None'

    provider_specific = get_provider_specific(protocolo, endpoint_conf)
    if provider_specific:
        wm = provider_specific.getDispatchPolicy()
        if not wm:
           wmDefault = wmDefault + 1
           workManager = 'default'
        else:
           workManager = wm

    return workManager

def set_workmanager(protocolo, endpoint_conf, wm):
    provider_specific = get_provider_specific(protocolo, endpoint_conf)
    if provider_specific:
        provider_specific.setDispatchPolicy(wm)
        endpoint_conf.setProviderSpecific(provider_specific)
        return True
    return False

def list_all_refs():
    all_refs = alsb_core.getRefs(Ref.DOMAIN)
    for r in all_refs:
        if r.getTypeId() == "BusinessService":
            list_business_service(r)
        if r.getTypeId() == "ProxyService":
            list_proxy_service(r)
        if r.getTypeId() == "Pipeline":
            list_pipeline(r)
    cross_reference_pipelines()

def cross_reference_pipelines():
    if verbose:
        print "Analizando Llamadas Locales a Pipelines sin Operacion o Selector...."
    for k,v in pipelines.items():
        for p in v['callsLocalPipeline']:
            if pipelines[p]['numBranches'] != 0 and pipelines[p]['selectorType'] == '-':
                pipelines[p]['needsSelector'] = 'SI'
                pipelines[k]['callsLocalNoOp'] = 'SI'

def list_business_service(ref):
    global wmDefault, businessFullTrace, businessHeadersTrace, connTimeOut, readTimeOut
    bs = ref.getFullName()
    if verbose:
        print "Analizando Business Service:",bs
    business[bs] = {}
    business[bs]['serviceEnabled'] = "NO"
    business[bs]['traceLevel'] = "-"
    business[bs]['connectionTimeOut'] = "-"
    business[bs]['readTimeOut'] = "-"
    
    business_entry = service_conf_mbean.getBusinessDefinition(ref).getBusinessServiceEntry()
    endpoint_conf = business_entry.getEndpointConfig()
    core_entry = business_entry.getCoreEntry()
    operations = BusinessOperationsBean(core_entry.getOperations())
 
    protocolo = endpoint_conf.getProviderId()
    business[bs]['protocol'] = protocolo
    business[bs]['workManager'] = get_workmanager(protocolo, endpoint_conf)

    # Timeouts solo para http
    if protocolo == "http":
        http_endpoint_conf = HttpUtil.getHttpConfig(endpoint_conf)
        http_outbound_props = http_endpoint_conf.getOutboundProperties()
        if http_outbound_props.isSetConnectionTimeout():
            http_connection_to = http_outbound_props.getConnectionTimeout()
            business[bs]['connectionTimeOut'] = http_connection_to
            if http_connection_to == 0:
                connTimeOut = connTimeOut + 1
        else:
            connTimeOut = connTimeOut + 1
        
        if http_outbound_props.isSetTimeout():
            http_read_to = http_outbound_props.getTimeout()
            business[bs]['readTimeOut'] = http_read_to
            if http_read_to == 0:
                readTimeOut = readTimeOut + 1
        else:
            readTimeOut = readTimeOut + 1
    
    if operations.getEnabled():
        business[bs]['serviceEnabled'] = "SI"

    if operations.getMessageTracingEnabled():
        traceLevel = operations.getMessageTracingLevel()
        business[bs]['traceLevel'] = traceLevel
        if traceLevel == "Full":
            businessFullTrace = businessFullTrace + 1
        elif traceLevel == "Headers":
            businessHeadersTrace = businessHeadersTrace + 1

def list_proxy_service(ref):
    global proxyFullTrace, proxyHeadersTrace
    ps = ref.getFullName()
    if verbose:
        print "Analizando Proxy Service:",ps
    proxys[ps] = {}
    proxys[ps]['traceLevel'] = "-"
    proxys[ps]['serviceEnabled'] = "NO"
    proxys[ps]['securityPolicy'] = "None"
    
    proxy_def = service_conf_mbean.getProxyDefinition(ref).getProxyServiceEntry()
    endpoint_conf = proxy_def.getEndpointConfig()
    core_entry = proxy_def.getCoreEntry()
    operations = ProxyOperationsBean(core_entry.getOperations())

    protocolo = endpoint_conf.getProviderId()
    proxys[ps]['protocol'] = protocolo
    proxys[ps]['workManager'] = get_workmanager(protocolo, endpoint_conf)

    if operations.getEnabled():
      proxys[ps]['serviceEnabled'] = "SI"

    if core_entry.isSetSecurity():
      security_entry = core_entry.getSecurity()
      access_control = security_entry.getAccessControlPolicies()
      if access_control and access_control.isSetTransportLevelPolicy():
          s = service_security_conf_mbean.newTransportPolicyScope(ref)
          proxys[ps]['securityPolicy'] = service_security_conf_mbean.getAccessControlPolicy(s, xacmlauth).getPolicyExpression()

    if operations.getMessageTracingEnabled():
        traceLevel =  operations.getMessageTracingLevel()
        proxys[ps]['traceLevel'] = traceLevel
        if traceLevel == "Full":
            proxysFullTrace = proxysFullTrace + 1
        elif traceLevel == "Headers":
            proxysHeadersTrace = proxysHeadersTrace + 1

def get_calls_pipeline_no_op(ns, match):
    pipes = []
    for m in match:
        s = m.selectChildren(ns, "service")
        ref = s[0].selectAttribute(javax.xml.namespace.QName("ref")).getStringValue()
        reftype = s[0].selectAttribute(javax.xml.namespace.QName("http://www.w3.org/2001/XMLSchema-instance","type")).getStringValue()
        o = m.selectChildren(ns, "operation")
        if reftype == 'con:PipelineRef' and len(o) == 0:
            pipes.append(ref)
    return pipes

def get_local_pipeline_calls(xml):
    localpipes = []
    ns = "http://www.bea.com/wli/sb/stages/routing/config"
    match = xml.selectPath("declare namespace rt='"+ns+"'; //rt:route")
    localpipes.extend(get_calls_pipeline_no_op(ns, match))
    ns = "http://www.bea.com/wli/sb/stages/transform/config"
    match = xml.selectPath("declare namespace tr='"+ns+"'; //tr:wsCallout")
    localpipes.extend(get_calls_pipeline_no_op(ns, match))
    return localpipes

def list_pipeline(ref):
    global pipelinesEnDebug
    pl = ref.getFullName()
    if verbose:
        print "Analizando Pipeline:",pl
    pipelines[pl] = {}
    pipelines[pl]['logLevel'] = '-'
    pipelines[pl]['traceEnabled'] = 'NO'
    pipelines[pl]['callsLocalPipeline'] = 'NO'
    pipelines[pl]['selectorType'] = '-'
    # Estas dos propiedades se completan en cross_reference_pipelines
    pipelines[pl]['needsSelector'] = 'NO'
    pipelines[pl]['callsLocalNoOp'] = 'NO'
    
    pipeline_def = pipeline_conf_mbean.getEntry(ref).getPipelineEntry()
    core_entry = pipeline_def.getCoreEntry()
    binding_entry = core_entry.getBinding()
    operations = PipelineOperationsBean(pipeline_def.getCoreEntry().getOperations())
    if operations.getTracingEnabled():
        pipelines[pl]['traceEnabled'] = 'SI'
    if operations.getLoggingEnabled():
        logLevel = operations.getLoggingLevel()
        pipelines[pl]['logLevel'] = logLevel
        if logLevel == 'DEBUG':
            pipelinesEnDebug = pipelinesEnDebug + 1
    if binding_entry.getType().toString() in ("SOAP","XML","Any SOAP") and binding_entry.isSetSelector():
        pipelines[pl]['selectorType'] = binding_entry.getSelector().getType()
    flow = pipeline_def.getRouter().getFlow()
    pipelines[pl]['numBranches'] = flow.sizeOfBranchNodeArray()
    pipelines[pl]['callsLocalPipeline'] = get_local_pipeline_calls(flow)

def save_reports():
    if verbose:
        print "Guardando reporte Proxy Services en",file_reporte_proxys
    f = codecs.open(file_reporte_proxys,'w','utf-8')
    f.write("#proxyService,protocol,workManager,enabled,traceLevel,securityPolicy\n")
    for k,v in proxys.items():
        f.write(k + ",%(protocol)s,%(workManager)s,%(serviceEnabled)s,%(traceLevel)s,\"%(securityPolicy)s\"\n"%v)
    f.close

    if verbose:
        print "Guardando reporte Business Services en",file_reporte_business
    f = codecs.open(file_reporte_business,'w','utf-8')
    f.write("#businessService,protocol,workManager,enabled,traceLevel,cTimeOut,rTimeOut\n")
    for k,v in business.items():
        f.write(k + ",%(protocol)s,%(workManager)s,%(serviceEnabled)s,%(traceLevel)s,%(connectionTimeOut)s,%(readTimeOut)s\n"%v)
    f.close

    if verbose:
        print "Guardando reporte Pipelines en",file_reporte_pipelines
    f = codecs.open(file_reporte_pipelines,'w','utf-8')
    f.write("#pipeline,traceEnabled,logLevel,needsSelector,callsLocalNoOp\n")
    for k,v in pipelines.items():
        f.write(k + ",%(traceEnabled)s,%(logLevel)s,%(needsSelector)s,%(callsLocalNoOp)s\n"%v)
    f.close

def load_pipelines_report():
    if verbose:
        print 'Leyendo reporte Pipelines de', file_reporte_pipelines
    f = codecs.open(file_reporte_pipelines,'r','utf-8')
    try:
      for line in f.readlines():
        ### Strip the comment lines
        if line.strip().startswith('#'):
            continue
        else:
            ### Split the comma seperated values
            items = line.split(',')
            items = [item.strip() for item in items]
            if len(items) != 5:
                print "==>Bad line: %s" % line
                print "==>Syntax: pipeline,traceEnabled,logLevel,needsSelector,callsLocalNoOp"
            else:
                pipelines[items[0]] = {} 
                pipelines[items[0]]['traceEnabled'] = boolean_uppercase(items[1], line)
                pipelines[items[0]]['logLevel'] = logLevel_or_dash(items[2], line)
                pipelines[items[0]]['needsSelector'] = boolean_uppercase(items[3], line)
                pipelines[items[0]]['callsLocalNoOp'] = boolean_uppercase(items[4], line)
    except Exception, e:
        print "==>Error Occured"
        print e

def number_or_dash(number, line):
    if number != '-':
        try:
            return int(number)
        except:
            print "==>Bad Number at line: %s" % line 
    return '-'

def traceLevel_or_dash(string, line):
    if string != '-':
        try:
            return MessageTracingLevel.valueOf(string)
        except:
            print "==>Bad Trace level at line: %s" % line 
    return '-'

def logLevel_or_dash(string, line):
    if string != '-':
        try:
            return LogSeverityLevel.valueOf(string)
        except:
            print "==>Bad Log level at line: %s" % line 
    return '-'

def boolean_uppercase(string, line):
    string = string.upper()
    if string in ('SI', 'NO'):
        return string
    print "==>Bad Boolean at line: %s" % line 
    return 'NO'
         
def load_business_report():
    if verbose:
        print 'Leyendo reporte Business de', file_reporte_business
    f = codecs.open(file_reporte_business,'r','utf-8')
    try:
      for line in f.readlines():
        ### Strip the comment lines
        if line.strip().startswith('#'):
            continue
        else:
            ### Split the comma seperated values
            items = line.split(',')
            items = [item.strip() for item in items]
            if len(items) != 7:
                print "==>Bad line: %s" % line
                print "==>Syntax: businessService,protocol,workManager,enabled,traceLevel,cTimeOut,rTimeOut"
            else:
                business[items[0]] = {} 
                business[items[0]]['protocol'] = items[1]
                business[items[0]]['workManager'] = items[2]
                business[items[0]]['serviceEnabled'] = boolean_uppercase(items[3], line)
                business[items[0]]['traceLevel'] = traceLevel_or_dash(items[4], line)
                business[items[0]]['connectionTimeOut'] = number_or_dash(items[5], line)
                business[items[0]]['readTimeOut'] = number_or_dash(items[6], line)
    except Exception, e:
        print "==>Error Occured"
        print e

def handle_comas(list):
    string = ','.join(list)
    return string

def load_proxys_report():
    if verbose:
        print 'Leyendo reporte Proxies de', file_reporte_proxys
    f = codecs.open(file_reporte_proxys,'r','utf-8')
    try:
      for line in f.readlines():
        ### Strip the comment lines
        if line.strip().startswith('#'):
            continue
        else:
            ### Split the comma seperated values
            items = line.split(',')
            items = [item.strip() for item in items]
            if len(items) > 6:
                items[5] = handle_comas(items[5:])
                del items[6:]
            if len(items) != 6:
                print "==>Bad line: %s" % line
                print "==>Syntax: proxyService,protocol,workManager,enabled,traceLevel,securityPolicy"
            else:
                proxys[items[0]] = {} 
                proxys[items[0]]['protocol'] = items[1]
                proxys[items[0]]['workManager'] = items[2]
                proxys[items[0]]['serviceEnabled'] = boolean_uppercase(items[3], line)
                proxys[items[0]]['traceLevel'] = traceLevel_or_dash(items[4], line)
                proxys[items[0]]['securityPolicy'] = items[5].strip('\"')
    except Exception, e:
        print "==>Error Occured"
        print e

def update_configurations(businessfunc, proxyfunc, pipelinefunc, comment):
    num_changed = 0
    tanda = 1
    create_session()

    all_refs = alsb_core.getRefs(Ref.DOMAIN)
    for r in all_refs:
        changed = False
        if r.getTypeId() == "BusinessService":
            changed = businessfunc(r)
        if r.getTypeId() == "ProxyService":
            changed = proxyfunc(r)
        if r.getTypeId() == "Pipeline":
            changed = pipelinefunc(r)

        if changed: 
            num_changed = num_changed + 1

        if num_changed > mods_per_session:
            activate_session("Tanda " + str(tanda) + " - " + comment)
            time.sleep(1)
            if verbose:
                print "---------- COMMIT Tanda " + str(tanda) + " OK ----------"
            create_session()
            num_changed = 0
            tanda = tanda + 1

    if num_changed != 0:
        activate_session("Tanda " + str(tanda) + " - " + comment)
        if verbose:
            print "---------- COMMIT Tanda " + str(tanda) + " OK ----------"

def no_update(ref):
    return False

def update_pipeline(ref):
    pl = ref.getFullName()
    if not pl in pipelines:
        return False
    if verbose:
        print "Evaluando cambios en Pipeline:",pl
    logLevel = '-'
    traceEnabled = 'NO'
    changed = False
    cambio = ''
    
    pipeline_def = pipeline_conf_mbean.getEntry(ref).getPipelineEntry()
    operations = PipelineOperationsBean(pipeline_def.getCoreEntry().getOperations())
    if operations.getTracingEnabled():
        traceEnabled = 'SI'
    if operations.getLoggingEnabled():
        logLevel = operations.getLoggingLevel()

    if pipelines[pl]['traceEnabled'] != traceEnabled:
        changed = True
        if pipelines[pl]['traceEnabled'] == 'SI':
            operations.setTracingEnabled(True)
        else:
            operations.setTracingEnabled(False)
        cambio = cambio + 'traceEnabled '

    if pipelines[pl]['logLevel'] != logLevel:
        changed = True
        if pipelines[pl]['logLevel'] == '-':
            operations.setLoggingEnabled(False)
        else:
            operations.setLoggingEnabled(True)
            operations.setLoggingLevel(pipelines[pl]['logLevel'])
        cambio = cambio + 'logLevel '
        
    if changed:
        if verbose:
            print "Cambiando",cambio,"en Pipeline:",pl
        pipeline_conf_mbean.updateOperations(ref, operations)
    return changed

def update_business(ref):
    bs = ref.getFullName()
    if not bs in business:
        return False
    if verbose:
        print "Evaluando cambios en Business:",bs
    serviceEnabled = "NO"
    traceLevel = "-"
    connectionTimeOut = "-"
    readTimeOut = "-"
    changed = False
    cambio = ''
    
    business_def = service_conf_mbean.getBusinessDefinition(ref)
    business_entry = business_def.getBusinessServiceEntry()
    endpoint_conf = business_entry.getEndpointConfig()
    core_entry = business_entry.getCoreEntry()
    operations = BusinessOperationsBean(core_entry.getOperations())
 
    protocolo = endpoint_conf.getProviderId()
    workManager = get_workmanager(protocolo, endpoint_conf)

    # Timeouts solo para http
    if protocolo == "http":
        http_endpoint_conf = HttpUtil.getHttpConfig(endpoint_conf)
        http_outbound_props = http_endpoint_conf.getOutboundProperties()
        if http_outbound_props.isSetConnectionTimeout():
            connectionTimeOut = http_outbound_props.getConnectionTimeout()
        if http_outbound_props.isSetTimeout():
            readTimeOut = http_outbound_props.getTimeout()
    
    if operations.getEnabled():
        serviceEnabled = "SI"

    if operations.getMessageTracingEnabled():
        traceLevel = operations.getMessageTracingLevel()

    if business[bs]['serviceEnabled'] != serviceEnabled:
        changed = True
        if business[bs]['serviceEnabled'] == 'SI':
            operations.setEnabled(True)
        else:
            operations.setEnabled(False)
        operations.apply(business_def)
        cambio = cambio + 'serviceEnabled '

    if business[bs]['traceLevel'] != traceLevel:
        changed = True
        if business[bs]['traceLevel'] == '-':
            operations.setMessageTracingEnabled(False)
        else:
            operations.setMessageTracingEnabled(True)
            operations.setMessageTracingLevel(business[bs]['traceLevel'])
        operations.apply(business_def)
        cambio = cambio + 'traceLevel '

    if protocolo == "http" and business[bs]['connectionTimeOut'] != connectionTimeOut:
        changed = True
        if business[bs]['connectionTimeOut'] == '-':
            http_outbound_props.unsetConnectionTimeout()
        else:
            http_outbound_props.setConnectionTimeout(business[bs]['connectionTimeOut'])
        endpoint_conf.setProviderSpecific(http_endpoint_conf)
        cambio = cambio + 'connectionTimeOut '

    if protocolo == "http" and business[bs]['readTimeOut'] != readTimeOut:
        changed = True
        if business[bs]['readTimeOut'] == '-':
            http_outbound_props.unsetTimeout()
        else:
            http_outbound_props.setTimeout(business[bs]['readTimeOut'])
        endpoint_conf.setProviderSpecific(http_endpoint_conf)
        cambio = cambio + 'readTimeOut '

    if business[bs]['workManager'] != workManager:
        changed = set_workmanager(protocolo, endpoint_conf, business[bs]['workManager'])
        if changed:
            cambio = cambio + 'workManager '

    if changed:
        if verbose:
            print "Cambiando",cambio,"en Business:",bs
        service_conf_mbean.updateService(ref, business_def)
    return changed

def update_proxy(ref):
    ps = ref.getFullName()
    if not ps in proxys:
        return False
    if verbose:
        print "Evaluando cambios en Proxy:",ps

    serviceEnabled = "NO"
    traceLevel = "-"
    securityPolicy = "None"
    changed = False
    cambio = ''

    proxy_def = service_conf_mbean.getProxyDefinition(ref)
    proxy_entry = proxy_def.getProxyServiceEntry()
    endpoint_conf = proxy_entry.getEndpointConfig()
    core_entry = proxy_entry.getCoreEntry()
    operations = ProxyOperationsBean(core_entry.getOperations())

    protocolo = endpoint_conf.getProviderId()
    workManager = get_workmanager(protocolo, endpoint_conf)

    if operations.getEnabled():
      serviceEnabled = "SI"

    if core_entry.isSetSecurity():
      security_entry = core_entry.getSecurity()
      access_control = security_entry.getAccessControlPolicies()
      if access_control and access_control.isSetTransportLevelPolicy():
          s = service_security_conf_mbean.newTransportPolicyScope(ref)
          securityPolicy = service_security_conf_mbean.getAccessControlPolicy(s, xacmlauth).getPolicyExpression()

    if operations.getMessageTracingEnabled():
        traceLevel =  operations.getMessageTracingLevel()
    
    if proxys[ps]['serviceEnabled'] != serviceEnabled:
        changed = True
        if proxys[ps]['serviceEnabled'] == 'SI':
            operations.setEnabled(True)
        else:
            operations.setEnabled(False)
        operations.apply(proxy_def)
        cambio = cambio + 'serviceEnabled '

    if proxys[ps]['traceLevel'] != traceLevel:
        changed = True
        if proxys[ps]['traceLevel'] == '-':
            operations.setMessageTracingEnabled(False)
        else:
            operations.setMessageTracingEnabled(True)
            operations.setMessageTracingLevel(proxys[ps]['traceLevel'])
        operations.apply(proxy_def)
        cambio = cambio + 'traceLevel '

    if proxys[ps]['workManager'] != workManager:
        changed = set_workmanager(protocolo, endpoint_conf, proxys[ps]['workManager'])
        if changed:
            cambio = cambio + 'workManager '

    if changed:
        if verbose:
            print "Cambiando",cambio,"en Proxy:",ps
        service_conf_mbean.updateService(ref, proxy_def)

    if proxys[ps]['securityPolicy'] != securityPolicy:
        if verbose:
            print "Cambiando securityPolicy en Proxy:",ps
        changedsp = set_security_policy(ref, proxys[ps]['securityPolicy'])
        if changedsp:
            cambio = cambio + 'securityPolicy '
            changed = True

    return changed

def verify_security_policy(sp):
    isok = True
    import re
    acls = sp.split('|')
    for acl in acls:
        op, arg = [part.strip() for part in re.split('[\(\)]', acl) if part.strip()]
        if op == 'Usr':
            isok = isok and verify_users(arg)
        elif op == 'Grp':
            print "====> Validacion de Grupos no implementada. Grp", arg
        else:
            print "====> Validacion de ACL no implementada.", op, arg
    return isok

def verify_users(arg):
    isok = True
    for user in arg.split(','):
        print user
    return isok

def usage():
    print "Use: %s [OPTIONS] "%sys.argv[0]
    print "List/Updates the configuration of proxies, business and pipelines of the osb domain."
    print "Example: %s -o list -s 192.168.1.10 -l 7010 -u usradm -p secret"%sys.argv[0]
    print "Example: %s --operation list --server 192.168.1.10 --listen_port 7010 --user_name usradm --password secret"%sys.argv[0]
    print "OPTIONS:"
    print "  -v --verbose"
    print "  -o --operation       list/updateps/updatebs/updatepipe/updateall"
    print "  -s --server          Server to connect"
    print "  -l --listen_address  Listen adress"
    print "  -u --user_name       User name"
    print "  -p --password        Password"
    print "  -f --rep_proxy       filenameProxies.csv"
    print "  -b --rep_business    filenameBusiness.csv"
    print "  -n --rep_pipelines   filenamePipelines.csv"
    print "  -c --comment         Comment in commits"
    print
    
def get_parameters():
    import getopt
    import sys

    operation, server, listen_port, user_name, password = '','','','',''
    global verbose, file_reporte_proxys, file_reporte_business, file_reporte_pipelines

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'vo:s:l:u:p:f:b:n:c:',
                ['verbose', 'operation=', 'server=', 'listen_port=', 'user_name=', 'password=', 'rep_proxy=', 'rep_business=', 'rep_pipelines=', 'comment='])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ('-v', '--verbose'):
            verbose = True
        elif opt in ('-o', '--operation'):
            operation = arg
        elif opt in ('-s', '--server'):
            server = arg
        elif opt in ('-l', '--listen_port'):
            listen_port = arg
        elif opt in ('-u', '--user_name'):
            user_name = arg
        elif opt in ('-p', '--password'):
            password = arg
        elif opt in ('-f', '--rep_proxy'):
            file_reporte_proxys = arg
        elif opt in ('-b', '--rep_business'):
            file_reporte_business = arg
        elif opt in ('-n', '--rep_pipelines'):
            file_reporte_pipelines = arg
        elif opt in ('-c', '--comment'):
            commit_comment = arg
        else:
            usage()
            sys.exit(2)

    if not (server and listen_port and user_name and password):
        print operation, server, listen_port, user_name, password
        usage()
        sys.exit(2)

    if operation not in ('list', 'updateps', 'updatebs', 'updatepipe', 'updateall'):
        print "operation not recognized:",operation
        usage()
        sys.exit(2)

    return operation, server, listen_port, user_name, password

def main():
    operation, server, listen_port, user_name, password = get_parameters()
#    operation, server, listen_port, user_name, password = "list", "127.0.0.1", 7601, "weblogic", "welcome1"

    for_update = operation != 'list'

    connector = connect_to_jmx(server, listen_port, user_name, password, for_update)
    if operation == 'list':
        list_all_refs()
        save_reports()
    elif operation == 'updatepipe':
        load_pipelines_report()
        update_configurations(no_update, no_update, update_pipeline, commit_comment)
    elif operation == 'updatebs':
        load_business_report()
        update_configurations(update_business, no_update, no_update, commit_comment)
    elif operation == 'updateps':
        load_proxys_report()
        update_configurations(no_update, update_proxy, no_update, commit_comment)
    elif operation == 'updateall':
        load_proxys_report()
        load_pipelines_report()
        load_business_report()
        update_configurations(update_business, update_proxy, update_pipeline, commit_comment)
    close_connection(connector, for_update)
    

if __name__ == "__main__" or __name__ == "main":
    main()
