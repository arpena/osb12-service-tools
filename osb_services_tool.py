#i! /usr/bin/env ./osbwlst.sh

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
# Version 1.3:
#   - Agregado workaround Bug 29469271 a los route nodes mediante operation pass through
#   - Se Refactorizaron los metodos de obtener informacion de todos los tipos de componente, para poderlos usar en los metodos de actualizacion
#   - Se modifico el update de pipelines para usar los nuevos metodos get_*
# Version 1.4:
#   - Se modifico el update de proxys para usar los nuevos metodos get_*
#   - Se verifica que el protocolo de los proxy continue siendo el mismo en el servidor y en el reporte para evitar confusiones
#   - Se verifica el cumplimento de las reglas de seguridad informatica en las politicas de seguridad
#   - Se agregó el modo de insercion de un usuario nuevo a un proxy en particular 
#   - Se agregó la operacion proxyinfo que da informacion sobre un proxy en particular
# Version 1.5:
#   - Se modifico el update de business para usar los nuevos metodos get_*
#   - Se agregó la URI, el tipo de autenticacion y si usa SSL a get_proxy_info y al reporte csv
#   - Se agregó la URI y el tipo de autenticacion a get_business_info y al reporte csv
#   - Se agregaron las funciones para obtener las dependencias entre servicios y pipelines
#   - Se agregó la operacion endpointuris que lista los proxys (no locales) y los business a los que terminan llamando con sus uris
#   - Se cambiaron todos los mensajes de progreso, debug y errores a stderr 
# Falta:
#   - Mejorar el manejo de workmanagers en otros protocolos, como MQ donde los proxys tienen 2 tipos de workmanager
#   - Crear comentarios en el commit mas descriptivos de los cambios realizados
#   - Poder eliminar la politica de seguridad de un proxy
#   - Agregar capacidad de mandar reporte resumido por mail/consola de cantidad de pipelines en debug, etc 
#   - Verificar existencia de usuarios y grupos en weblogic realm
#   - Crear usuario en weblogic ream cuando se agrega uno con adduser
#   - Agregar campo de validez de politica de seguridad en reporte proxys
#   - Hacer las funciones de cargar los reportes dinamicas con los headers. Eso permitiria hacer CSVs parciales sin todas las columnas
#   - Agregar generacion de archivo SVG

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
from com.bea.wli.config.resource import ResourceQuery
from com.bea.wli.sb.management.query import ProxyServiceQuery
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
from com.bea.wli.config.env import EnvValueQuery, QualifiedEnvValue
from com.bea.wli.config.resource import DependencyQuery
from com.bea.wli.sb.util import EnvValueTypes
import codecs
import re
import getopt
import sys

# Configuracion
file_reporte_proxys = 'reporteProxyServices.csv'
file_reporte_business = 'reporteBusinessServices.csv'
file_reporte_pipelines = 'reportePipelines.csv'
mods_per_session = 10
session_name = 'osbwlst_'+sys.argv[0]
commit_comment = ''
env = 'prod'

# Variables Globales
proxys, business, pipelines, dependencies = {}, {}, {}, {}
pipelinesEnDebug = 0
businessFullTrace, businessHeadersTrace, connTimeOut, readTimeOut, wmDefault = 0, 0, 0, 0, 0
proxyFullTrace, proxyHeadersTrace = 0, 0
verbose = False

alsb_core, service_conf_mbean, service_security_conf_mbean, xacmlauth, default_auth, pipeline_conf_mbean, session_mgmt_mbean = '','','','','','',''

def get_mbean_server_connection(hostname, port, username, password):
    if verbose:
        print >> sys.stderr, "Conectandome al servidor de jmx..."
    jmx_service_url = JMXServiceURL("t3", hostname, port, "/jndi/%s"%DomainRuntimeServiceMBean.MBEANSERVER_JNDI_NAME)
    credentials_map = HashMap()
    credentials_map.put(Context.SECURITY_PRINCIPAL, username)
    credentials_map.put(Context.SECURITY_CREDENTIALS, password)
    credentials_map.put(JMXConnectorFactory.PROTOCOL_PROVIDER_PACKAGES, "weblogic.management.remote")
    return  JMXConnectorFactory.connect(jmx_service_url, credentials_map)

def close_connection(conn, for_update):
    if verbose:
        print >> sys.stderr, "Cerrando la conexion jmx..."
    if for_update:
        discard_session()
    conn.close()

def get_conf_mbean(conn, mbean_class, sessionId):
    conf_name = ObjectName("com.bea:Name=" + mbean_class.NAME + sessionId  + ",Type=" + mbean_class.TYPE)
    mbeans = HashSet()
    mbeans.addAll( conn.queryNames(conf_name, None) )
    return  MBeanServerInvocationHandler.newProxyInstance(conn, mbeans.iterator().next(), mbean_class, false)

def set_security_policy(ref, policy):
#    if verify_security_policy(policy):
        policyHolder = service_security_conf_mbean.newAccessControlPolicyHolderInstance("XACMLAuthorizer")
        policyHolder.setPolicyExpression(policy)
        policyScope = service_security_conf_mbean.newTransportPolicyScope(ref)
        service_security_conf_mbean.setAccessControlPolicy(policyScope,policyHolder)
        return True
#    return False

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
        elif r.getTypeId() == "ProxyService":
            list_proxy_service(r)
        elif r.getTypeId() == "Pipeline":
            list_pipeline(r)
    cross_reference_pipelines()

def cross_reference_pipelines():
    if verbose:
        print >> sys.stderr, "Analizando Llamadas Locales a Pipelines sin Operacion o Selector...."
    for k,v in pipelines.items():
        for p in v['callsLocalPipeline'].keys():
            if pipelines[p]['numBranches'] != 0 and pipelines[p]['selectorType'] == '-':
                pipelines[p]['needsSelector'] = 'SI'
                pipelines[k]['callsLocalNoOp'] = 'SI'
        for p in v['routesLocalPipeline'].keys():
            if pipelines[p]['numBranches'] != 0 and pipelines[p]['selectorType'] == '-':
                pipelines[p]['needsSelector'] = 'SI'
                pipelines[k]['routesLocalNoOp'] = 'SI'

def get_business_info(ref):
    info = {
        'serviceEnabled': 'NO',
        'traceLevel': '-',
        'connectionTimeOut': '-',
        'readTimeOut': '-',
        'uri': 'None',
        'authType': 'None',
    }
    business_entry = service_conf_mbean.getBusinessDefinition(ref).getBusinessServiceEntry()
    endpoint_conf = business_entry.getEndpointConfig()
    core_entry = business_entry.getCoreEntry()
    operations = BusinessOperationsBean(core_entry.getOperations())
    if endpoint_conf.sizeOfURIArray() >= 1:
        info['uri'] = endpoint_conf.getURIArray(0).getValue()
    info['protocol'] = endpoint_conf.getProviderId()
    info['workManager'] = get_workmanager(info['protocol'], endpoint_conf)
    # Timeouts y tipo de autenticacion solo para http
    if info['protocol'] == 'http':
        http_conf = HttpUtil.getHttpConfig(endpoint_conf)
        info['authType'] = get_auth_type(http_conf)
        http_outbound_props = http_conf.getOutboundProperties()
        if http_outbound_props.isSetConnectionTimeout():
            info['connectionTimeOut'] = http_outbound_props.getConnectionTimeout()
        if http_outbound_props.isSetTimeout():
            info['readTimeOut'] = http_outbound_props.getTimeout()
    if operations.getEnabled():
        info['serviceEnabled'] = "SI"
    if operations.getMessageTracingEnabled():
        info['traceLevel'] = operations.getMessageTracingLevel()
    return info

def list_business_service(ref):
    global wmDefault, businessFullTrace, businessHeadersTrace, connTimeOut, readTimeOut
    bs = ref.getFullName()
    if verbose:
        print >> sys.stderr, "Analizando Business Service:",bs
    business[bs] = get_business_info(ref)
    if business[bs]['protocol'] == "http":
        if business[bs]['connectionTimeOut'] in (0, '-'):
            connTimeOut = connTimeOut + 1
        if business[bs]['readTimeOut'] in (0, '-'):
            readTimeOut = readTimeOut + 1
    if business[bs]['traceLevel'] == "Full":
        businessFullTrace = businessFullTrace + 1
    elif business[bs]['traceLevel'] == "Headers":
        businessHeadersTrace = businessHeadersTrace + 1

def get_auth_type(http_conf):
    auth = ''
    if http_conf.isSetInboundProperties():
        auth = http_conf.getInboundProperties().getClientAuthentication()
    elif http_conf.isSetOutboundProperties():
        auth = http_conf.getOutboundProperties().getOutboundAuthentication()
    if auth and 'HttpBasicAuthentication' in auth.getClass().getName():
        return 'Basic'
    elif auth and 'SSLClientAuthentication' in auth.getClass().getName():
        return 'SSLClient'
    elif auth:
        return 'Custom'
    else:
        return 'None'

def get_proxy_info(ref):
    info = {
        'traceLevel': '-',
        'serviceEnabled': 'NO',
        'securityPolicy': 'None',
        'uri': 'None',
        'isHTTPS': 'NO',
        'authType': 'None',
    } 
    proxy_def = service_conf_mbean.getProxyDefinition(ref).getProxyServiceEntry()
    endpoint_conf = proxy_def.getEndpointConfig()
    core_entry = proxy_def.getCoreEntry()
    operations = ProxyOperationsBean(core_entry.getOperations())
    if endpoint_conf.sizeOfURIArray() >= 1:
        info['uri'] = endpoint_conf.getURIArray(0).getValue()
    info['protocol'] = endpoint_conf.getProviderId()
    info['workManager'] = get_workmanager(info['protocol'], endpoint_conf)
    if info['protocol'] == 'http':
        http_conf = HttpUtil.getHttpConfig(endpoint_conf)
        if HttpUtil.isHttpsEndpoint(http_conf):
            info['isHTTPS'] = 'SI'
        info['authType'] = get_auth_type(http_conf)
    if operations.getEnabled():
        info['serviceEnabled'] = 'SI'
    if core_entry.isSetSecurity():
        security_entry = core_entry.getSecurity()
        access_control = security_entry.getAccessControlPolicies()
        if access_control and access_control.isSetTransportLevelPolicy():
            s = service_security_conf_mbean.newTransportPolicyScope(ref)
            info['securityPolicy'] = service_security_conf_mbean.getAccessControlPolicy(s, xacmlauth).getPolicyExpression()
    if operations.getMessageTracingEnabled():
        info['traceLevel'] = operations.getMessageTracingLevel()
    return info

def list_proxy_service(ref):
    global proxyFullTrace, proxyHeadersTrace
    ps = ref.getFullName()
    if verbose:
        print >> sys.stderr, "Analizando Proxy Service:",ps
    proxys[ps] = get_proxy_info(ref)
    if proxys[ps]['traceLevel'] == "Full":
        proxysFullTrace = proxysFullTrace + 1
    elif proxys[ps]['traceLevel'] == "Headers":
        proxysHeadersTrace = proxysHeadersTrace + 1

def get_calls_pipeline_no_op(ns, match):
    pipes = {}
    for m in match:
        s = m.selectChildren(ns, "service")
        ref = s[0].selectAttribute(javax.xml.namespace.QName("ref")).getStringValue()
        reftype = s[0].selectAttribute(javax.xml.namespace.QName("http://www.w3.org/2001/XMLSchema-instance","type")).getStringValue()
        o = m.selectChildren(ns, "operation")
        if reftype == 'con:PipelineRef' and len(o) == 0:
            pipes[ref] = 1
    return pipes

def get_local_pipeline_calls(xml):
    ns = "http://www.bea.com/wli/sb/stages/transform/config"
    match = xml.selectPath("declare namespace tr='"+ns+"'; //tr:wsCallout")
    return get_calls_pipeline_no_op(ns, match)

def get_local_pipeline_routes(xml):
    ns = "http://www.bea.com/wli/sb/stages/routing/config"
    match = xml.selectPath("declare namespace rt='"+ns+"'; //rt:route")
    return get_calls_pipeline_no_op(ns, match)

def get_pipeline_info(ref):
    info = {
        'logLevel': '-',
        'traceEnabled': 'NO',
        'selectorType': '-',
        # Estas tres propiedades se completan en cross_reference_pipelines
        'needsSelector': 'NO',
        'callsLocalNoOp': 'NO',
        'routesLocalNoOp': 'NO'
    }
    pipeline_def = pipeline_conf_mbean.getEntry(ref).getPipelineEntry()
    core_entry = pipeline_def.getCoreEntry()
    binding_entry = core_entry.getBinding()
    operations = PipelineOperationsBean(pipeline_def.getCoreEntry().getOperations())
    if operations.getTracingEnabled():
        info['traceEnabled'] = 'SI'
    if operations.getLoggingEnabled():
        logLevel = operations.getLoggingLevel()
        info['logLevel'] = logLevel
    if binding_entry.getType().toString() in ("SOAP","XML","Any SOAP") and binding_entry.isSetSelector():
        info['selectorType'] = binding_entry.getSelector().getType()
    flow = pipeline_def.getRouter().getFlow()
    info['numBranches'] = flow.sizeOfBranchNodeArray()
    info['callsLocalPipeline'] = get_local_pipeline_calls(flow)
    info['routesLocalPipeline'] = get_local_pipeline_routes(flow)
    return info

def list_pipeline(ref):
    global pipelinesEnDebug
    pl = ref.getFullName()
    if verbose:
        print >> sys.stderr, "Analizando Pipeline:",pl
    pipelines[pl] = get_pipeline_info(ref)
    if pipelines[pl]['logLevel'] == 'DEBUG':
        pipelinesEnDebug = pipelinesEnDebug + 1

def save_reports():
    if verbose:
        print >> sys.stderr, "Guardando reporte Proxy Services en",file_reporte_proxys
    f = codecs.open(file_reporte_proxys,'w','utf-8')
    f.write("#proxyService,protocol,workManager,enabled,traceLevel,uri,isHTTPS,authType,securityPolicy\n")
    for k,v in proxys.items():
        f.write(k + ",%(protocol)s,%(workManager)s,%(serviceEnabled)s,%(traceLevel)s,%(uri)s,%(isHTTPS)s,%(authType)s,\"%(securityPolicy)s\"\n"%v)
    f.close

    if verbose:
        print >> sys.stderr, "Guardando reporte Business Services en",file_reporte_business
    f = codecs.open(file_reporte_business,'w','utf-8')
    f.write("#businessService,protocol,workManager,enabled,traceLevel,cTimeOut,rTimeOut,uri,authType\n")
    for k,v in business.items():
        f.write(k + ",%(protocol)s,%(workManager)s,%(serviceEnabled)s,%(traceLevel)s,%(connectionTimeOut)s,%(readTimeOut)s,%(uri)s,%(authType)s\n"%v)
    f.close

    if verbose:
        print >> sys.stderr, "Guardando reporte Pipelines en",file_reporte_pipelines
    f = codecs.open(file_reporte_pipelines,'w','utf-8')
    f.write("#pipeline,traceEnabled,logLevel,needsSelector,routesLocalNoOp,callsLocalNoOp\n")
    for k,v in pipelines.items():
        f.write(k + ",%(traceEnabled)s,%(logLevel)s,%(needsSelector)s,%(routesLocalNoOp)s,%(callsLocalNoOp)s\n"%v)
    f.close

def load_pipelines_report():
    if verbose:
        print >> sys.stderr, 'Leyendo reporte Pipelines de', file_reporte_pipelines
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
            if len(items) != 6:
                print >> sys.stderr, "==>Bad line: %s" % line
                print >> sys.stderr, "==>Syntax: pipeline,traceEnabled,logLevel,needsSelector,routesLocalNoOp,callsLocalNoOp"
            else:
                pipelines[items[0]] = { 
                        'traceEnabled': boolean_uppercase(items[1], line),
                        'logLevel': logLevel_or_dash(items[2], line),
                        'needsSelector': boolean_uppercase(items[3], line),
                        'routesLocalNoOp': boolean_uppercase(items[4], line),
                        'callsLocalNoOp': boolean_uppercase(items[5], line),
                }
    except Exception, e:
        print >> sys.stderr, "==>Error Occured"
        print >> sys.stderr, e

def number_or_dash(number, line):
    if number != '-':
        try:
            return int(number)
        except:
            print >> sys.stderr, "==>Bad Number at line: %s" % line 
    return '-'

def traceLevel_or_dash(string, line):
    if string != '-':
        try:
            return MessageTracingLevel.valueOf(string)
        except:
            print >> sys.stderr, "==>Bad Trace level at line: %s" % line 
    return '-'

def logLevel_or_dash(string, line):
    if string != '-':
        try:
            return LogSeverityLevel.valueOf(string)
        except:
            print >> sys.stderr, "==>Bad Log level at line: %s" % line 
    return '-'

def boolean_uppercase(string, line):
    string = string.upper()
    if string in ('SI', 'NO'):
        return string
    print >> sys.stderr, "==>Bad Boolean at line: %s" % line 
    return 'NO'
         
def load_business_report():
    if verbose:
        print >> sys.stderr, 'Leyendo reporte Business de', file_reporte_business
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
            if len(items) != 9:
                print >> sys.stderr, "==>Bad line: %s" % line
                print >> sys.stderr, "==>Syntax: businessService,protocol,workManager,enabled,traceLevel,cTimeOut,rTimeOut,uri,authType"
            else:
                business[items[0]] = { 
                        'protocol': items[1],
                        'workManager': items[2],
                        'serviceEnabled': boolean_uppercase(items[3], line),
                        'traceLevel': traceLevel_or_dash(items[4], line),
                        'connectionTimeOut': number_or_dash(items[5], line),
                        'readTimeOut': number_or_dash(items[6], line),
                        'uri': items[7],
                        'authType': items[8],
                }
    except Exception, e:
        print >> sys.stderr, "==>Error Occured"
        print >> sys.stderr, e

def handle_comas(list):
    string = ','.join(list)
    return string

def load_proxys_report():
    if verbose:
        print >> sys.stderr, 'Leyendo reporte Proxies de', file_reporte_proxys
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
            if len(items) > 9:
                items[8] = handle_comas(items[8:])
                del items[9:]
            if len(items) != 9:
                print >> sys.stderr, "==>Bad line: %s" % line
                print >> sys.stderr, "==>Syntax: proxyService,protocol,workManager,enabled,traceLevel,uri,isHTTPS,authType,securityPolicy"
            else:
                proxys[items[0]] = { 
                        'protocol': items[1],
                        'workManager': items[2],
                        'serviceEnabled': boolean_uppercase(items[3], line),
                        'traceLevel': traceLevel_or_dash(items[4], line),
                        'uri': items[5],
                        'isHTTPS': boolean_uppercase(items[6], line),
                        'authType': items[7],
                        'securityPolicy': items[8].strip('\"'),
                }
    except Exception, e:
        print >> sys.stderr, "==>Error Occured"
        print >> sys.stderr, e

def update_configurations(businessfunc, proxyfunc, pipelinefunc, comment):
    num_changed = 0
    tanda = 1
    create_session()

    all_refs = alsb_core.getRefs(Ref.DOMAIN)
    for r in all_refs:
        changed = False
        if r.getTypeId() == "BusinessService":
            changed = businessfunc(r)
        elif r.getTypeId() == "ProxyService":
            changed = proxyfunc(r)
        elif r.getTypeId() == "Pipeline":
            changed = pipelinefunc(r)

        if changed: 
            num_changed = num_changed + 1

        if num_changed > mods_per_session:
            activate_session("Tanda " + str(tanda) + " - " + comment)
            time.sleep(1)
            if verbose:
                print >> sys.stderr, "---------- COMMIT Tanda " + str(tanda) + " OK ----------"
            create_session()
            num_changed = 0
            tanda = tanda + 1

    if num_changed != 0:
        activate_session("Tanda " + str(tanda) + " - " + comment)
        if verbose:
            print >> sys.stderr, "---------- COMMIT Tanda " + str(tanda) + " OK ----------"

def no_update(ref):
    return False

def boolean_from_string(s):
    if s == 'SI':
        return True
    return False

def update_pipeline_routes(xml, dest):
    changed = False
    # Keep only destinations that are problematic
    for d in dest.keys():
        path, localName = os.path.split(d)
        query = ResourceQuery('Pipeline')
        query.setPath(path)
        query.setLocalName(localName)
        refs = alsb_core.getRefs(query)
        if refs.size() != 1:
            print >> sys.stderr, "==> No existe el destino del route:", d
            del dest[d]
            continue
        if verbose:
            print >> sys.stderr, "Evaluando destino route:", d
        info = get_pipeline_info(refs[0])
        if info['numBranches'] == 0 or info['selectorType'] != '-':
            del dest[d]

    ns = "http://www.bea.com/wli/sb/stages/routing/config"
    match = xml.selectPath("declare namespace rt='"+ns+"'; //rt:route")
    for m in match:
        s = m.selectChildren(ns, "service")
        ref = s[0].selectAttribute(javax.xml.namespace.QName("ref")).getStringValue()
        reftype = s[0].selectAttribute(javax.xml.namespace.QName("http://www.w3.org/2001/XMLSchema-instance","type")).getStringValue()
        o = m.selectChildren(ns, "operation")
        if reftype == 'con:PipelineRef' and len(o) == 0 and ref in dest:
            if verbose:
                print >> sys.stderr, "Agregando passThrough al route a", ref
            addpassThrough(ns, m)
            changed = True
    return changed

def addpassThrough(ns, m):
    cur = m.newCursor()
    cur.toChild(ns, "service")
    cur.toNextSibling()
    cur.beginElement("operation", ns)
    cur.insertAttributeWithValue("passThrough", "true")
    cur.dispose()

def update_pipeline(ref):
    pl = ref.getFullName()
    if not pl in pipelines:
        return False
    if verbose:
        print >> sys.stderr, "Evaluando cambios en Pipeline:",pl
    info = get_pipeline_info(ref)
    mods = dict([ (k, pipelines[pl][k]) for k in pipelines[pl].keys() if pipelines[pl][k] != info[k] ])
    if not mods:
        return False

    pipeline_entry = pipeline_conf_mbean.getEntry(ref)
    pipeline_def = pipeline_entry.getPipelineEntry() 
    operations = PipelineOperationsBean(pipeline_def.getCoreEntry().getOperations())
    changed_ops = False
    changed_entry = False

    for k,v in mods.items():
        if k == 'traceEnabled':
            changed_ops = True
            operations.setTracingEnabled(boolean_from_string(v))
        elif k == 'logLevel':
            changed_ops = True
            if v == '-':
                operations.setLoggingEnabled(False)
            else:
                operations.setLoggingEnabled(True)
                operations.setLoggingLevel(v)
        elif k == 'routesLocalNoOp':
            changed_entry = update_pipeline_routes(pipeline_entry, info['routesLocalPipeline'])
    if changed_entry:
        if verbose:
            print >> sys.stderr, "Actualizando rutas en Pipeline:",pl
        pipeline_conf_mbean.updateEntry(ref, pipeline_entry)
    if changed_ops:
        if verbose:
            print >> sys.stderr, "Cambiando",' '.join(mods.keys()),"en Pipeline:",pl
        pipeline_conf_mbean.updateOperations(ref, operations)
    return changed_entry or changed_ops

def update_business(ref):
    bs = ref.getFullName()
    if not bs in business:
        return False
    if verbose:
        print >> sys.stderr, "Evaluando cambios en Business:",bs
    info = get_business_info(ref)
    mods = dict([ (k, business[bs][k]) for k in business[bs].keys() if business[bs][k] != info[k] ])
    if not mods:
        return False

    changed = False
    business_def = service_conf_mbean.getBusinessDefinition(ref)
    business_entry = business_def.getBusinessServiceEntry()
    endpoint_conf = business_entry.getEndpointConfig()
    core_entry = business_entry.getCoreEntry()
    operations = BusinessOperationsBean(core_entry.getOperations())
    protocolo = endpoint_conf.getProviderId()

    # Timeouts solo para http
    if protocolo == "http":
        http_endpoint_conf = HttpUtil.getHttpConfig(endpoint_conf)
        http_outbound_props = http_endpoint_conf.getOutboundProperties()

    for k,v in mods.items():
        if k == 'serviceEnabled':
            changed = True
            operations.setEnabled(boolean_from_string(v))
        elif k == 'traceLevel':
            changed = True
            if v == '-':
                operations.setMessageTracingEnabled(False)
            else:
                operations.setMessageTracingEnabled(True)
                operations.setMessageTracingLevel(v)
        elif k == 'workManager':
            changed = set_workmanager(protocolo, endpoint_conf, v)
        elif k == 'connectionTimeOut' and protocolo == 'http':
            changed = True
            if v == '-':
                http_outbound_props.unsetConnectionTimeout()
            else:
                http_outbound_props.setConnectionTimeout(v)
            endpoint_conf.setProviderSpecific(http_endpoint_conf)
        elif k == 'readTimeOut' and protocolo == 'http':
            changed = True
            if v == '-':
                http_outbound_props.unsetTimeout()
            else:
                http_outbound_props.setTimeout(v)
            endpoint_conf.setProviderSpecific(http_endpoint_conf)
        elif k in ('protocol', 'uri', 'authType'):
            print >> sys.stderr, "==> Error: Cambio de",k,"en Business:", ps
            print >> sys.stderr, "==> Ignorando todos los cambios"
            return False
    if changed:
        if verbose:
            print >> sys.stderr, "Cambiando",' '.join(mods.keys()),"en Business:",ps
        operations.apply(business_def)
        service_conf_mbean.updateService(ref, business_def)
    return changed

def update_proxy(ref):
    ps = ref.getFullName()
    if not ps in proxys:
        return False
    if verbose:
        print >> sys.stderr, "Evaluando cambios en Proxy:",ps
    info = get_proxy_info(ref)
    mods = dict([ (k, proxys[ps][k]) for k in proxys[ps].keys() if proxys[ps][k] != info[k] ])
    if not mods:
        return False

    proxy_def = service_conf_mbean.getProxyDefinition(ref)
    proxy_entry = proxy_def.getProxyServiceEntry()
    endpoint_conf = proxy_entry.getEndpointConfig()
    core_entry = proxy_entry.getCoreEntry()
    operations = ProxyOperationsBean(core_entry.getOperations())
    changed = False
    changed_sp = False

    for k,v in mods.items():
        if k == 'serviceEnabled':
            changed = True
            operations.setEnabled(boolean_from_string(v))
            core_entry.setOperations(operations.toOperationsType())
        elif k == 'traceLevel':
            changed = True
            if v == '-':
                operations.setMessageTracingEnabled(False)
            else:
                operations.setMessageTracingEnabled(True)
                operations.setMessageTracingLevel(v)
            core_entry.setOperations(operations.toOperationsType())
        elif k == 'workManager':
            changed = set_workmanager(protocolo, endpoint_conf, v)
        elif k in ('protocol', 'uri', 'isHTTPS', 'authType'):
            print >> sys.stderr, "==> Error: Cambio de",k,"en Proxy:", ps
            print >> sys.stderr, "==> Ignorando todos los cambios"
            return False
        elif k == 'securityPolicy' and v == 'None':
            print >> sys.stderr, "==> No debe eliminarse el securityPolicy en Proxy:", ps
            print >> sys.stderr, "==> Ignorando el cambio"
            del mods[k]

    if changed:
        if verbose:
            print >> sys.stderr, "Cambiando",' '.join(mods.keys()),"en Proxy:",ps
        service_conf_mbean.updateService(ref, proxy_def)

    if 'securityPolicy' in mods:
        if verbose:
            print >> sys.stderr, "Actualizando securityPolicy en Proxy:",ps
        changed_sp = set_security_policy(ref, mods['securityPolicy'])

    return changed or changed_sp

def find_proxy_ref(ps):
    path, localName = os.path.split(ps)
    query = ProxyServiceQuery()
    query.setPath(path)
    query.setLocalName(localName)
    refs = alsb_core.getRefs(query)
    if refs.size() != 1:
        return False
    return refs[0]

def add_user_to_proxy(ps, user):
    if not verify_user(user):
        return
    if verbose:
        print >> sys.stderr, "Analizando Proxy:", ps
    ref = find_proxy_ref(ps)
    if not ref:
        print >> sys.stderr, "==> No existe el proxy:", ps
        return
    info = get_proxy_info(ref)
    securityPolicy = info['securityPolicy']
    if securityPolicy == 'None':
        print >> sys.stderr, "==> No se puede agregar politica de seguridad al proxy:",ps
        return
    securityPolicy = securityPolicy + "|Usr("+user+")"
    if verbose:
        print >> sys.stderr, "Actualizando securityPolicy en Proxy:",ps
    set_security_policy(ref, securityPolicy)
    if verbose:
        print >> sys.stderr, "Activando sesion"
    activate_session("Se agrego usuario " + user + " en proxy " + ps)

def print_proxy_info(ps):
    if verbose:
        print >> sys.stderr, "Analizando Proxy:", ps
    ref = find_proxy_ref(ps)
    if not ref:
        print >> sys.stderr, "==> No existe el proxy:", ps
        return
    info = get_proxy_info(ref)
    print "Proxy:", ps
    print "Protocolo: %(protocol)s\nWorkmanager: %(workManager)s\nHabilitado: %(serviceEnabled)s"%info
    if verify_security_policy(info['securityPolicy']):
        valid = "Valida"
    else:
        valid = "Invalida"
    print "Politica de seguridad ("+valid+"): %(securityPolicy)s"%info

def verify_security_policy(sp):
    if sp == 'None':
        return True

    isok = True
    acls = sp.split('|')
    for acl in acls:
        op, arg = [part.strip() for part in re.split('[\(\)]', acl) if part.strip()]
        if op == 'Usr':
            isok = isok and verify_users(arg)
        elif op == 'Grp':
            print >> sys.stderr, "====> Validacion de Grupos no implementada. Grp", arg
        else:
            print >> sys.stderr, "====> Validacion de ACL no implementada.", op, arg
    return isok

def verify_users(arg):
    isok = True
    for user in arg.split(','):
        isok = isok and verify_user(user)
    return isok

def verify_user(user):
    m = re.search('^(.)(\D*)(\d\d)m$', user)
    if m:
        pre,cmdb,num = m.groups()
        return verify_user_prefix(pre, user)
    m = re.search('^(.*)grecobus$', user)
    if m:
        pre = m.group(1)
        return verify_user_prefix(pre, user)
    print >> sys.stderr, "==> User not in proper format:", user
    return False

def verify_user_prefix(pre, user):
    if env == 'prod':
        if pre in ('u', 'prod'):
            return True
    elif env == 'homo':
        if pre in ('t', 'homo'):
            return True
    print >> sys.stderr, "==> Invalid user:",user,"in environment", env
    return False

# Funciones para determinar dependencia entre servicios

def get_dependents(ref):
    dep = []
    dep_query = DependencyQuery(Collections.singleton(ref), false)
    refs = alsb_core.getRefs(dep_query)
    for r in refs:
        if r.getTypeId() in ('BusinessService', 'ProxyService', 'Pipeline'):
            dep.append(r)
    return dep

def get_all_dependencies():
    global dependencies
    dependencies = {}
    all_refs = alsb_core.getRefs(Ref.DOMAIN)
    for r in all_refs:
        if r.getTypeId() in ('BusinessService', 'ProxyService', 'Pipeline'):
            dependencies[r] = { 'dep': get_dependents(r),
                                'out': 0,
                                'in': 0,
                                }

def get_in_out_degree():
    global dependencies
    for r,n in dependencies.items():
        n['out'] = len(n['dep'])
        for d in n['dep']:
            if not dependencies[d]:
                dependencies[d] = { 'dep': [],
                                    'out': 0,
                                    'in': 0
                                    }
            dependencies[d]['in'] += 1

def get_business_nodes(ref, l=None):
    if l == None:
        l = []
    for r in dependencies[ref]['dep']:
        if dependencies[r]['out'] == 0:
            if r.getTypeId() == 'BusinessService':
                l.append(r)
        else:
            get_business_nodes(r,l)
    return l

def list_endpoint_uris():
    global dependencies
    get_all_dependencies()
    get_in_out_degree()
    # Lista de nodos raiz ordenada por nombre completo
    l = [ r for r in dependencies.keys() if dependencies[r]['in'] == 0 and dependencies[r]['out'] != 0 ]
    l.sort(lambda x,y: cmp(x.getFullName(), y.getFullName()))
    for origin in l:
        if origin.getTypeId() != 'ProxyService':
            print >> sys.stderr, "==> Origin not ProxyService!", origin
            continue
        infops = get_proxy_info(origin)
        if infops['uri'] == 'None':
            continue
        for dest in get_business_nodes(origin):
            infobs = get_business_info(dest)
            print "%s:%s ---> %s:%s"%(origin.getFullName(),infops['uri'],dest.getFullName(),infobs['uri'])

def usage():
    print >> sys.stderr, "Use: %s [OPTIONS] "%sys.argv[0]
    print >> sys.stderr, "List/Updates the configuration of proxies, business and pipelines of the osb domain."
    print >> sys.stderr, "Example: %s -o list -s 192.168.1.10 -l 7010 -u usradm -p secret"%sys.argv[0]
    print >> sys.stderr, "Example: %s --operation list --server 192.168.1.10 --listen_port 7010 --user_name usradm --password secret"%sys.argv[0]
    print >> sys.stderr, "OPTIONS:"
    print >> sys.stderr, "  -v --verbose"
    print >> sys.stderr, "  -o --operation       list/updateps/updatebs/updatepipe/updateall/proxyinfo/adduser/endpointuris"
    print >> sys.stderr, "  -s --server          Server to connect"
    print >> sys.stderr, "  -l --listen_address  Listen adress"
    print >> sys.stderr, "  -u --user_name       User name"
    print >> sys.stderr, "  -p --password        Password"
    print >> sys.stderr, "  -f --rep_proxy       filenameProxies.csv (default reporteProxyServices.csv)"
    print >> sys.stderr, "  -b --rep_business    filenameBusiness.csv (default reporteBusinessServices.csv)"
    print >> sys.stderr, "  -n --rep_pipelines   filenamePipelines.csv (default reportePipelines.csv)"
    print >> sys.stderr, "  -c --comment         Comment in commits (default \"\")"
    print >> sys.stderr, " Options for proxyinfo/adduser:"
    print >> sys.stderr, "  --proxy              Proxy to get/set security info"
    print >> sys.stderr, "  --add_user           User to add to proxy"
    print >> sys.stderr, "  --env                prod/homo (default prod)"
    print >> sys.stderr
    
def get_parameters():
    operation, server, listen_port, user_name, password, proxy_to_mod, user_to_add = '','','','','','',''
    global verbose, file_reporte_proxys, file_reporte_business, file_reporte_pipelines, env

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'vo:s:l:u:p:f:b:n:c:',
                ['verbose', 'operation=', 'server=', 'listen_port=', 'user_name=', 'password=', 'rep_proxy=', 'rep_business=', 'rep_pipelines=', 'comment=', 'proxy=', 'add_user=', 'env='])
    except getopt.GetoptError:
        print >> sys.stderr, "==> GetoptError!"
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
        elif opt == '--proxy':
            proxy_to_mod = arg
        elif opt == '--add_user':
            user_to_add = arg
        elif opt == '--env':
            env = arg
        else:
            print >> sys.stderr, "==> Unrecognized option", opt, arg
            usage()
            sys.exit(2)

    if not (server and listen_port and user_name and password):
        usage()
        sys.exit(2)

    if operation not in ('list', 'updateps', 'updatebs', 'updatepipe', 'updateall', 'proxyinfo', 'adduser', 'endpointuris'):
        print >> sys.stderr, "==> Operation not recognized:",operation
        usage()
        sys.exit(2)

    if operation == 'proxyinfo' and not proxy_to_mod:
        print >> sys.stderr, "==> --proxy argument is required"
        usage()
        sys.exit(2)

    if operation == 'adduser' and (not proxy_to_mod or not user_to_add):
        print >> sys.stderr, "==> --proxy and --add_user arguments are required"
        usage()
        sys.exit(2)

    return operation, server, listen_port, user_name, password, proxy_to_mod, user_to_add

def main():
    operation, server, listen_port, user_name, password, proxy_to_mod, user_to_add = get_parameters()
#    operation, server, listen_port, user_name, password = "list", "127.0.0.1", 7601, "weblogic", "welcome1"

    for_update = operation not in ('list', 'proxyinfo', 'endpointuris')

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
    elif operation == 'proxyinfo':
        print_proxy_info(proxy_to_mod)
    elif operation == 'adduser':
        add_user_to_proxy(proxy_to_mod, user_to_add)
    elif operation == 'endpointuris':
        list_endpoint_uris()
    close_connection(connector, for_update)
    

if __name__ == "__main__" or __name__ == "main":
    main()
