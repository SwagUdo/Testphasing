from qiling import Qiling
from qiling.const import QL_VERBOSE
import sys

EPOLL_FD = 200

#эта хрень не работает
def debug(msg):
    print(f"[QILING] {msg}", file=sys.stderr)

#эта хрень тоже не работает
def hook_epoll_create(ql, size):
    debug(f"epoll_create(size={size}) -> fd={EPOLL_FD}")
    ql.os.set_syscall_return(EPOLL_FD)

# тут чето выдало, но я этого не понимаю
def hook_ioctl(ql, fd, request, arg):
    debug(
        f"ioctl(fd={fd}, request=0x{request:x}, arg=0x{arg:x}) -> 0"
    )
    ql.os.set_syscall_return(0)

#и все изза того что ubuntu на меня обижалась
ql = Qiling(
    ["/opt/rootfs/usr/sbin/nginx", "-c", "/etc/nginx/nginx.conf"],
    "/opt/rootfs",
    verbose=QL_VERBOSE.DEFAULT,
    multithread=True
)

ql.os.set_syscall('epoll_create', hook_epoll_create)
ql.os.set_syscall('ioctl', hook_ioctl)

ql.run()