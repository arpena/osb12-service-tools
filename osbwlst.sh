#! /bin/sh

if [ -z "$ALSB_HOME" -o -z "$WLS_HOME" ]; then
  echo "Por favor correr el setDomainEnv.sh del dominio"
  exit 1
fi

WLS_NOT_BRIEF_ENV=false
export WLS_NOT_BRIEF_ENV

for i in $ALSB_HOME/lib/modules/*.jar; do
  WLST_EXT_CLASSPATH=${i}${CLASSPATHSEP}${WLST_EXT_CLASSPATH}
done
for i in $ALSB_HOME/lib/transports/*.jar; do
  WLST_EXT_CLASSPATH=${i}${CLASSPATHSEP}${WLST_EXT_CLASSPATH}
done

WLST_EXT_CLASSPATH=${WLS_HOME}/lib/wlclient.jar${CLASSPATHSEP}${WLST_EXT_CLASSPATH}

export WLST_EXT_CLASSPATH

${COMMON_COMPONENTS_HOME}/common/bin/wlst.sh "$@"

