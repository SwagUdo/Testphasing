from qiling import Qiling
from qiling.const import QL_VERBOSE
#Qiling ЧЕРТ ВОЗЬМИ НЕ РАБОТАЕТ
ql = Qiling(
    ["/opt/rootfs/bin/hello"],
    "/opt/rootfs",
    verbose=QL_VERBOSE.DEFAULT
)

ql.run()