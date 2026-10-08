import os
import select
import socket
import struct
import sys
import threading
import time

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.exception import QlErrorNotImplemented
from qiling.os.posix.syscall.socket import ql_syscall_accept
from qiling.extensions.afl import ql_afl_fuzz_custom

ROOTFS = "/opt/rootfs"
NGINX_BIN = "/opt/rootfs/usr/sbin/nginx"
NGINX_CONF = "/etc/nginx/nginx.conf"

HOST = "127.0.0.1"
PORT = 8080

MAX_INSTRUCTIONS = 2_000_000

SOCK_NONBLOCK = 0x800

#include/uapi/asm-generic/ioctls.h тут всякие такие коды
FIONBIO = 0x5421

SOL_SOCKET = 1
SO_TYPE = 3

DEBUG_ENABLED = os.environ.get(
    "QILING_DEBUG",
    "0",
) == "1"


def debug(message: str) -> None:
    if DEBUG_ENABLED:
        print(
            f"[QILING-AFL] {message}",
            file=sys.stderr,
            flush=True,
        )


current_input = b""
current_input_offset = 0

input_exhausted = False

fuzzing_started = False

process_request_address = 0

# пытаемся ловить ioctl, и если Nginx просит включить/настроить или еще чего FIONBIO (режим сокета),
#  Qiling просто даст успешный результат 0, а любой другой запрос уйдет через -1.

def hook_ioctl(
    ql,
    fd,
    request,
    arg,
):
    if request == FIONBIO:
        debug(
            f"ioctl(FIONBIO, fd={fd}) -> 0"
        )
        return 0

    return -1

# пытаемся хватать getsockopt и тут Nginx спрашивает тип сокета,
#  он вроде как запишит значение SOCK_STREAM и длину 4 байта? наверно,
#  после чего сообщит об успешном выполнении 0 остальные запросы забьет -1
# да i это 4 байт
def hook_getsockopt(
    ql,
    sockfd,
    level,
    optname,
    optval,
    optlen,
):
    if level == SOL_SOCKET and optname == SO_TYPE:
        debug(
            f"getsockopt(fd={sockfd}, SO_TYPE) "
            f"-> SOCK_STREAM"
        )

        ql.mem.write(
            optval,
            struct.pack(
                "<i",
                socket.SOCK_STREAM,
            ),
        )
        #там вообще 4 байта?
        ql.mem.write(
            optlen,
            struct.pack(
                "<I",
                4,
            ),
        )

        return 0

    return -1

#accept4 это типо системный вызов где то в Linux, 
#который принимает новое входящее соединение на вроде как сокете, месте соединения

# тут пытаюсь перехватить accept4, оно принимает новое соединение через Qiling,
#  получаем адрес подключившегося кого то
#  и записывает его в память, но не обычную эмулятора надеюсь, в формате типо sockaddr_in;
#  затем, если был указан флаг SOCK_NONBLOCK,
#  переводит новый сокет в неблокирующий режим и по идеи возвращает его какие то файлы
def hook_accept4(
    ql,
    sockfd,
    addr,
    addrlenptr,
    flags,
):

    new_fd = ql_syscall_accept(
        ql,
        sockfd,
        addr,
        addrlenptr,
    )

    debug(
        f"accept4(fd={sockfd}) -> emulated fd={new_fd}"
    )

    if new_fd < 0:
        return new_fd

    sock_obj = ql.os.fd[new_fd]

    if sock_obj is None:
        return -1

    try:
        peer_host, peer_port = sock_obj.getpeername()

        if sock_obj.family != socket.AF_INET:
            return -1
# < младший байт или как то так
# ! это типо интернетовские байты какие то
        sockaddr_in = (
            struct.pack(
                "<H",
                socket.AF_INET,
            )
            + struct.pack(
                "!H",
                peer_port,
            )
            + socket.inet_aton(
                peer_host,
            )
            + (b"\x00" * 8)
        )

        ql.mem.write(
            addr,
            sockaddr_in,
        )

        ql.mem.write(
            addrlenptr,
            struct.pack(
                "<I",
                16,
            ),
        )

    except Exception as exc:
        debug(
            "адрес вообще не сработал "
            f"{type(exc).__name__}: {exc}"
        )
        return -1

    if flags & SOCK_NONBLOCK:
        try:
            sock_obj.socket.setblocking(False)
        except OSError as exc:
            debug(
                "адрес обиделся: "
                f"{type(exc).__name__}: {exc}"
            )
            return -1

    return new_fd

#Хук пытается перехватывать recv (еще одна какая то системная штука linux, которая вроде является принятием соединения)
# и вместо того что бы вообще что то читать там, он из сокета по идеи должен
#  взять очередную порцию текущего AFL-теста (current_input) и кароче так тест и будет происходить
#  AFL должен как то эти данные там сам менять и процесс будет происходить.
#  пытаемся записать это все в память Qiling, а потом нужно как то типо сдвинуть чтение и типо сказать
#  что вход закончился, все данные переданы и все хорошо
#  затем возвращает количество переданных данных и это вроде как байты

def hook_recv(
    ql,
    fd,
    buf,
    length,
    flags,
):

    global current_input
    global current_input_offset
    global input_exhausted

    data = current_input[
        current_input_offset:
    ]

    chunk = data[:length]

    if chunk:
        ql.mem.write(
            buf,
            chunk,
        )

        current_input_offset += len(chunk)

    if current_input_offset >= len(current_input):
        input_exhausted = True

    debug(
        f"recv(fd={fd}, length={length}) "
        f"-> {len(chunk)} bytes: {chunk[:64]!r}"
    )

    return len(chunk)

#а тут мне надо повторить процесс, но при это что бы он мог а адресом работать, я
# не знаю, может AFL вообще не захочет сюда заходить или чето делать,
#  но пишут такое нужно делать
def hook_recvfrom(
    ql,
    fd,
    buf,
    length,
    flags,
    addr,
    addrlen,
):

    global current_input
    global current_input_offset
    global input_exhausted

    data = current_input[
        current_input_offset:
    ]

    chunk = data[:length]

    if chunk:
        ql.mem.write(
            buf,
            chunk,
        )

        current_input_offset += len(chunk)

    if current_input_offset >= len(current_input):
        input_exhausted = True

    debug(
        f"recvfrom(fd={fd}, length={length}) "
        f"-> {len(chunk)} bytes: {chunk[:64]!r}"
    )

    return len(chunk)


#хоть бы это хоть как то запусилось
#вот этот вот хук должен че то типо "подменять" ожидание событий на разных точках соединения:
#во время всего действия он сразу говорит Nginx, что основная точка fd=3 готов к работе, все с ним хорошо,
#а когда AFL закончит чето делать, тест должен закончится по идеи, надеюсь
#вне вот этого всего действия он должен просто делать обычную работу pselect6 в select.select
def hook_pselect6(
    ql,
    nfds,
    readfds,
    writefds,
    exceptfds,
    timeout,
    sigmask,
):

    def parse_fd_set(ptr):
        fd_list = []
        fd_map = {}

        if not ptr:
            return fd_list, fd_map

        for emu_fd in range(nfds):
            byte_addr = ptr + (
                emu_fd // 8
            )

            byte_value = ql.mem.read(
                byte_addr,
                1,
            )[0]

            if not (
                byte_value
                & (1 << (emu_fd % 8))
            ):
                continue

            if emu_fd >= len(ql.os.fd):
                continue

            file_obj = ql.os.fd[emu_fd]

            if file_obj is None:
                continue

            try:
                host_fd = file_obj.fileno()
            except Exception:
                continue

            fd_list.append(host_fd)
            fd_map[host_fd] = emu_fd

        return fd_list, fd_map

    def write_fd_set(
        ptr,
        ready_fds,
        fd_map,
    ):
        if not ptr:
            return

        size = (nfds + 7) // 8

        result = bytearray(
            b"\x00" * size
        )

        for host_fd in ready_fds:
            emu_fd = fd_map.get(host_fd)

            if emu_fd is None:
                continue

            result[
                emu_fd // 8
            ] |= (
                1 << (emu_fd % 8)
            )

        ql.mem.write(
            ptr,
            bytes(result),
        )

    if fuzzing_started:

        if input_exhausted:
            debug(
                "AFL input сказал, что ничего не видит "
                "ngx_http_process_request; "
                "stopping testcase"
            )

            ql.uc.emu_stop()

            return 0

        read_size = (
            nfds + 7
        ) // 8

        if readfds:
            result = bytearray(
                b"\x00" * read_size
            )

            if 3 < nfds:
                result[
                    3 // 8
                ] |= (
                    1 << (3 % 8)
                )

            ql.mem.write(
                readfds,
                bytes(result),
            )

        if writefds:
            ql.mem.write(
                writefds,
                bytes(
                    b"\x00" * read_size
                ),
            )

        if exceptfds:
            ql.mem.write(
                exceptfds,
                bytes(
                    b"\x00" * read_size
                ),
            )

        debug(
            "pselect6(AFL): "
            "emulated fd=3"
        )

        return 1


    read_fds, read_map = parse_fd_set(
        readfds
    )

    write_fds, write_map = parse_fd_set(
        writefds
    )

    except_fds, except_map = parse_fd_set(
        exceptfds
    )

    if timeout:
        sec = ql.mem.read_ptr(
            timeout
        )

        nsec = ql.mem.read_ptr(
            timeout + 8
        )

        timeout_total = (
            sec
            + float(nsec)
            / 1_000_000_000
        )

    else:
        timeout_total = None

    try:
        ready_r, ready_w, ready_e = (
            select.select(
                read_fds,
                write_fds,
                except_fds,
                timeout_total,
            )
        )

    except OSError as exc:
        debug(
            "вот не получается: "
            f"{type(exc).__name__}: {exc}"
        )
        return -1

    write_fd_set(
        readfds,
        ready_r,
        read_map,
    )

    write_fd_set(
        writefds,
        ready_w,
        write_map,
    )

    write_fd_set(
        exceptfds,
        ready_e,
        except_map,
    )

    return (
        len(ready_r)
        + len(ready_w)
        + len(ready_e)
    )

#тут нужно взять запись данных pwrite64, 
#надо как взять то указанные в count данные из памяти Qiling
#и попытаться записать их куда нибудь в offset,
#а если вообще чето не так пойдет просто пусть сообщает об успехе иначе все ломается
def hook_pwrite64(
    ql,
    fd,
    buf,
    count,
    offset,
):

    try:
        file_obj = ql.os.fd[fd]

        if file_obj is None:
            return count

        data = ql.mem.read(
            buf,
            count,
        )

        if hasattr(file_obj, "seek"):
            file_obj.seek(offset)

        if hasattr(file_obj, "write"):
            result = file_obj.write(data)

            if result is None:
                return count

            return int(result)

    except Exception as exc:
        debug(
            "вот что в этот раз не нравится: "
            f"{type(exc).__name__}: {exc}"
        )

    return count

def place_input_callback(
    ql,
    input_bytes,
    persistent_round,
):

    global current_input
    global current_input_offset
    global input_exhausted

    current_input = bytes(
        input_bytes
    )

    current_input_offset = 0
    input_exhausted = False

    debug(
        f"testcase #{persistent_round}: "
        f"len={len(current_input)} "
        f"data={current_input[:32]!r}"
    )

    return True

#так, надо как то запустить afl
#кароче здесь буду пытаться запустить AFLтест
#поставить ограничение на сколько раз он там проведет фигню
#если что то пойдет не так нафиг все закрою и там надо смотреть, что делать

def fuzzing_callback(
    ql,
):

    global process_request_address

    if process_request_address == 0:
        raise RuntimeError(
            "ох, что то с адресом или получение адреса"
        )

    if hasattr(
        ql.arch.regs,
        "arch_pc",
    ):
        pc = ql.arch.regs.arch_pc
    else:
        pc = ql.arch.regs.rip

    debug(
        f"стартует PC=0x{pc:x}"
    )

    try:
        ql.uc.emu_start(
            pc,
            0,
            0,
            MAX_INSTRUCTIONS,
        )

    except Exception as exc:
        debug(
            "вот что пошло не так: "
            f"{type(exc).__name__}: {exc}"
        )

        os.abort()

    debug(
        "вроде прошло, все завершилось"
    )

    return 0

#оказывается nginx просто так посидеть посмотреть или подождать не может
#пишут ему нужно какое то соединение, всегда, вот выдавлю какоето соединение
#он должен будет быть в рабочем состояние а потому AFL все равно все поменяет

bootstrap_socket = None
bootstrap_ready = threading.Event()


def bootstrap_client():

    global bootstrap_socket

    sock = None

    try:
        for _ in range(200):

            try:
                sock = socket.create_connection(
                    (
                        HOST,
                        PORT,
                    ),
                    timeout=0.2,
                )
                break

            except (
                ConnectionRefusedError,
                TimeoutError,
                OSError,
            ):
                time.sleep(
                    0.025
                )

        if sock is None:
            debug(
                f"bootstrap: failed to connect "
                f"to {HOST}:{PORT}"
            )
            return

        sock.settimeout(2.0)


        sock.sendall(
            b"\x00"
        )

        bootstrap_socket = sock
        bootstrap_ready.set()

        debug(
            "bootstrap: TCP connection established"
        )

        while True:
            time.sleep(
                1.0
            )

    except Exception as exc:
        debug(
            "bootstrap client error: "
            f"{type(exc).__name__}: {exc}"
        )

    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

#тут надо мне каждый раз при написании какого то хука, который придумает мое воображение
#регистрировать его
#как я понял, это вообще не просто регистрация это вообще замена действий которые происходят в nginx
def main(
    input_file: str,
):
    global fuzzing_started
    global process_request_address

    debug(
        f"input file: {input_file}"
    )

    ql = Qiling(
        [
            NGINX_BIN,
            "-c",
            NGINX_CONF,
        ],
        ROOTFS,
        verbose=QL_VERBOSE.OFF,
        console=False,
        multithread=True,
    )


    ql.bindtolocalhost = True


    ql.os.set_syscall(
        "ioctl",
        hook_ioctl,
    )

    ql.os.set_syscall(
        "getsockopt",
        hook_getsockopt,
    )

    ql.os.set_syscall(
        "pselect6",
        hook_pselect6,
    )

    ql.os.set_syscall(
        "accept4",
        hook_accept4,
    )

    ql.os.set_syscall(
        "recv",
        hook_recv,
    )

    ql.os.set_syscall(
        "recvfrom",
        hook_recvfrom,
    )

    ql.os.set_syscall(
        "pwrite64",
        hook_pwrite64,
    )

    symbols = {}

    try:
        with os.popen(
            f"nm -n {NGINX_BIN}"
        ) as pipe:

            for line in pipe:
                parts = line.split()

                if len(parts) < 3:
                    continue

                try:
                    address = int(
                        parts[0],
                        16,
                    )

                except ValueError:
                    continue

                symbols[
                    parts[2]
                ] = address

    except Exception as exc:
        raise RuntimeError(
            "Unable to read Nginx symbols"
        ) from exc

    required = [
        "ngx_unix_recv",
        "ngx_http_process_request",
    ]

    for name in required:
        if name not in symbols:
            raise RuntimeError(
                f"Nginx symbol not found: {name}"
            )


    base = ql.loader.images[0].base

    recv_address = (
        base
        + symbols["ngx_unix_recv"]
    )

    process_request_address = (
        base
        + symbols["ngx_http_process_request"]
    )

    debug(
        "ngx_unix_recv: "
        f"0x{recv_address:x}"
    )

    debug(
        "ngx_http_process_request: "
        f"0x{process_request_address:x}"
    )


    def start_afl(
        _ql,
    ):
        global fuzzing_started


        if fuzzing_started:
            debug(
                "так, afl уже запущен "
                "continuing into ngx_unix_recv"
            )
            return

        fuzzing_started = True

        debug(
            "все попытка не пытка, afl запускается"
        )

        ql_afl_fuzz_custom(
            _ql,
            input_file=input_file,
            place_input_callback=place_input_callback,
            fuzzing_callback=fuzzing_callback,

            exits=[
                process_request_address
            ],

            persistent_iters=1,
        )

        os._exit(0)


    ql.hook_address(
        callback=start_afl,
        address=recv_address,
    )


    client = threading.Thread(
        target=bootstrap_client,
        daemon=True,
    )

    client.start()

    debug(
        "nginx делает свои дела"
    )


    try:
        ql.run()

    except QlErrorNotImplemented as exc:
        debug(
            "qiling обижается, чето ему не хватает"
            f"{exc}"
        )
        return 1

    except Exception as exc:
        debug(
            "qiling сломался, вот решай вот это: "
            f"{type(exc).__name__}: {exc}"
        )
        return 1

    return 0


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(
            f"usage: {sys.argv[0]} <afl-input-file>",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(
        main(
            sys.argv[1]
        )
    )