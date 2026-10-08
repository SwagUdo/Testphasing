import select
import socket
import struct
import sys
import threading
import time

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.posix.syscall.socket import ql_syscall_accept


ROOTFS = "/opt/rootfs" #тут типо корень для эмулятора
NGINX_BIN = "/opt/rootfs/usr/sbin/nginx" #а тут сам nginx исполняемый
NGINX_CONF = "/etc/nginx/nginx.conf"

HOST = "127.0.0.1"
PORT = 8080

#я десятки раз всю свою память забил
RUN_TIMEOUT_US = 5_000_000

#grep -R "FIONBIO" /usr/include | head
FIONBIO = 0x5421
SOL_SOCKET = 1
SO_TYPE = 3
SOCK_NONBLOCK = 0x800

MAX_PWRITE_DEBUG = 5
pwrite_debug_count = 0


def debug(message: str) -> None:
    print(
        f"[QILING] {message}",
        file=sys.stderr,
        flush=True,
    )

#nginx почему то, я не разобрался блокировал меня, вот пусть ПРОСТО НЕ БЛОКИРУЕТ
def hook_ioctl(ql, fd, request, arg):
    if request == FIONBIO:
        debug(
            f"ioctl(FIONBIO, fd={fd}) -> 0"
        )
        return 0

    return -1

#зайдя нужен сокет, штекер соединения и тут Я ПРОСТО ЗАСТАВЛЯЮ ЕГО ПРИНЯТЬ, ЧТО ВСЕ НОРМАЛЬНО ЭТО НОРМ СОКЕТ
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

        ql.mem.write(
            optlen,
            struct.pack(
                "<I",
                4,
            ),
        )

        return 0

    return -1

#Этот хук нужен, чтобы Nginx под Qiling мог ждать 
#хоть какие то действия.Он типо смотрит состояние сокетов и сообщает
#вот с этим сокетом все нормально, можешь начать уже чето делать
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
            byte_addr = ptr + (emu_fd // 8)

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

            result[emu_fd // 8] |= (
                1 << (emu_fd % 8)
            )

        ql.mem.write(
            ptr,
            bytes(result),
        )

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
        sec = ql.mem.read_ptr(timeout)
        nsec = ql.mem.read_ptr(
            timeout + 8
        )

        timeout_total = (
            sec
            + float(nsec) / 1_000_000_000
        )
    else:
        timeout_total = None

    try:
        ready_r, ready_w, ready_e = select.select(
            read_fds,
            write_fds,
            except_fds,
            timeout_total,
        )
    except OSError as exc:
        debug(
            "он не нашел какой то байт нужный в сокете"
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

#я кароче беру соединени и меняю его так, что бы это принял NGINX
#он ещё исправляет адрес клиента и следит, чтобы сокет НЕ БЛОКИРОВАЛСЯ
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

    if new_fd < 0:
        return new_fd

    sock_obj = ql.os.fd[new_fd]

    if sock_obj is None:
        return -1

    try:
        peer_host, peer_port = sock_obj.getpeername()

        if sock_obj.family != socket.AF_INET:
            return -1

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
                peer_host
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
            "адрес не тот "
            f"{type(exc).__name__}: {exc}"
        )
        return -1

    if flags & SOCK_NONBLOCK:
        try:
            sock_obj.socket.setblocking(
                False
            )
        except OSError:
            return -1

    return new_fd

#тут я пытаюсь чето записать, хоть какой то ответ который типо улетит в Qiling
def hook_pwrite64(
    ql,
    fd,
    buf,
    count,
    offset,
):
    global pwrite_debug_count

    if pwrite_debug_count < MAX_PWRITE_DEBUG:
        pwrite_debug_count += 1

        try:
            data = ql.mem.read(
                buf,
                min(count, 64),
            )
            preview = data.decode(
                "utf-8",
                errors="replace",
            )
        except Exception:
            preview = "нифига не может прочитать"

        debug(
            f"pwrite64(fd={fd}, count={count}, "
            f"offset={offset}, data={preview!r})"
        )

        if pwrite_debug_count == MAX_PWRITE_DEBUG:
            debug(
                "ниче не отправилось больше"
            )

    try:
        file_obj = ql.os.fd[fd]
        data = ql.mem.read(
            buf,
            count,
        )

        if hasattr(file_obj, "seek"):
            file_obj.seek(offset)

        if hasattr(file_obj, "write"):
            result = file_obj.write(data)

            if result is None:
                result = count

            return int(result)

    except Exception:
        pass

    return count

#тут stdin должен получить файлы и прочитать их если все сложится
def read_stdin() -> bytes:
    data = sys.stdin.buffer.read()

    debug(
        f"stdin: {len(data)} bytes"
    )

    return data


def client_thread(
    input_data,
    finished,
    ql,
):
    sock = None

    try:
        for _ in range(200):
            if finished.is_set():
                return

            try:
                sock = socket.create_connection(
                    (HOST, PORT),
                    timeout=0.2,
                )
                break

            except (
                ConnectionRefusedError,
                TimeoutError,
                OSError,
            ):
                time.sleep(0.025)

        if sock is None:
            debug(
                f"Nginx не открылся"
                f"{HOST}:{PORT}"
            )
            return

        debug("Клиент подключили")

        sock.settimeout(2.0)

        sock.sendall(input_data)

        debug(
            f"Клиент отправил {len(input_data)} байтов"
        )

        response = bytearray()

        try:
            chunk = sock.recv(8192)

            if chunk:
                response.extend(chunk)

        except socket.timeout:
            debug("Клиент не отвечает")

        debug(
            f"клиент получил "
            f"{len(response)} байтов"
        )

        if response:
            preview = response[:256].decode(
                "utf-8",
                errors="replace",
            )

            debug(
                f"Ответ клиента={preview!r}"
            )

        finished.set()

        try:
            ql.stop()
        except Exception:
            pass

    except Exception as exc:
        debug(
            f"ошибка клиента"
            f"{type(exc).__name__}: {exc}"
        )

        finished.set()

        try:
            ql.stop()
        except Exception:
            pass

    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def main():
    input_data = read_stdin()

    finished = threading.Event()

    debug("создаем qiling")

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
        "pwrite64",
        hook_pwrite64,
    )

    debug(
        "стартует клиентскую передачу"
    )

    client = threading.Thread(
        target=client_thread,
        args=(
            input_data,
            finished,
            ql,
        ),
        daemon=True,
    )

    client.start()

    debug(
        "стартуем эмуляцию nginx"
    )

    try:
        ql.run(
            timeout=RUN_TIMEOUT_US
        )
    except Exception as exc:
        debug(
            f"qiling не нравится вот это: "
            f"{type(exc).__name__}: {exc}"
        )
        return 1
    finally:
        finished.set()

    client.join(timeout=1.0)

    debug("ОНО СРАБОТАЛО!")

    return 0


if __name__ == "__main__":
    sys.exit(main())

#region
# import sys #без этой блиблиотеки я не смогу вообще ничего
# from qiling import Qiling #надеюсь он ухватит qiling, вообще найдет его
# from qiling.const import QL_VERBOSE #это должно выводить инфу
#endregion

# region
# LISTEN_FD = 150 #nginx должен выдавать здесь типо 0
# CONN_FD = 151 # а тут выдать 1
# endregion

# region
#так что я просто рандомные числа пока здесь вставлю, что покажет
# здесь происходят те самые системные вызовы, должен быть socket()
 # и тут должен пройти accept() и словить 151 или 150? я рыбак?
#socket() - подключится (вставить)
#bind() - привязывает ( типо к localhost )
#listen() - о это типо пингонуть
#accept() - принять соединение

# def debug(msg): #с помощью этого, я должен увидеть все вызовы
#     print(f"[QILING] {msg}", file=sys.stderr)
#f - formatted string literals так могу засунуть переменную в текст
#QILING я подпишу, что бы я понимал, что от QILING я это получаю
#file=sys.stderr что бы нормальный текст вышел, а не то что там было

#держать в голове
# hook_bind типо я делаю успешную привязку
# hook_listen типо я прослушиваю
# hook_accept типо принимаю
# hook_read типо читаю
# hook_write типо пишу 
# hook_close типо закрываю
# hook_epoll_* вот это я не понял
#чето типо паузы? жди пока начнем работать?

#это системные штуки (команды), syscall
# открыть, прочитать, записать файл (open, read, write)
# создать сокет и передать данные по сети (socket, bind, send, recv)
# чертова память (mmap, brk)
# создать (fork, clone)

# вот он типо получил 150, привязываем? наверно
# создаем коробку socket(), точнее типо ловим ее, она уже есть?
# ql - сам управляет эмуляцией
# domain - адрес, домэйн? вроде частое слово, а я никак его не разберу
# sock_type - у них типы есть? черт
# protocol - по идеи там ничего нет, ну просто так напишу
# def hook_socket(ql, domain, sock_type, protocol): 
#     debug(f"socket() -> fd={LISTEN_FD}") #тут я попробую получить 150
#     ql.os.set_syscall_return(LISTEN_FD)#ql.os.set_syscall_return когда эмулируемая программа получит результат этого системного вызова, возвращай че получил?

# После создания сокета (socket() вернул 150) 
# эта фигня должна привязать этот сокет к конкретному адресу? и порту? или чему?
# я по идеи должен попросить ql, сделать так, что все нормально
# я привязал не беспокойся
# debug(f"socket() -> fd={LISTEN_FD}") это теперь sockfd
# addr - типо 120.0.0.0.1:чето
# addrlen - типо 120.0.0.0.1:чето = столько то
# def hook_bind(ql, sockfd, addr, addrlen):#кароче если я словлю 150 и превращу его в чето
#     debug(f"bind(fd={sockfd}) -> 0") # то получается получив то чето, я смогу увидеть, что все сработало
#     ql.os.set_syscall_return(0)# дай бог он этот 0 мне покажет

#че там с последовательностью
# вот он привязался, теперь будет сидеть слушать? listen кароче
#backlog - длина очереди, тех кто хочет присоединится? тяжело
# def hook_listen(ql, sockfd, backlog):
#     debug(f"listen(fd={sockfd}) -> 0")
#     ql.os.set_syscall_return(0) #пофигу все в 0 превращу

#Так, теперь сложнее, вот пришел кто то
#получается на каждого кого надо слушать, надо делать сокет
#он же подключается, сокет это подключение или я глупый
#значит мне надо попросить ql, закинька мне кого то кто хочет подключится?
#После listen всегда идет accept, только так он может чето принять
# def hook_accept(ql, sockfd, addr, addrlen):
#     global accepted #Если сигнал придет, получается тот станет true?
#     if not accepted: #вот он принял
#         accepted = True
#         debug(f"accept() -> new connection fd={CONN_FD}")#примет?
#         ql.os.set_syscall_return(CONN_FD)#151
#     else: #вот он не принял
#         # в линуксах ошибки выставляются типо в минусовых числах
#         # эти ошибки сохраняются где то в errno, а он где то там в системе

#         debug("accept() -> EAGAIN")
#         ql.os.set_syscall_return(-1) # 0 оказывается что то делает, там оказывается отрицательное уже надо писать

# ошибки в линуксе
# EBADF (9) неправильный файловый дескриптор, типо не прочитает
# EINTR (4) системный вызов прерван
# EAGAIN (11) не соединился
# ENOMEM (12) чето с памятью
# EACCES (13) нет доступа
# EIO (5) инпут, аутпут ошибки, ввели фигню
# ECONNREFUSED (111) отказ в соединение
# EOF (0) чето с концом файла связанно
# ETIMEDOUT (110) тайм аут


#теперь он кого то принял, типо принял
#получается должен прочитать? или там он при accept сразу чето получает?
#увидел, там типо http запрос, но у меня нет типо реального соединения и что и как кого
# def hook_read(ql, fd, buf, count):
#fd - чето встроенное в системе, типо дескриптер?
#buf - я типо получаимое что то, должен выделять память, а buf типо адрес выдает памяти?
#count - этим я буду говорить, сколько прочитать по идеи
    # if fd == CONN_FD:#это мое соединение? да
    #     data = ql.os.fd[0].read(count)# вот типо тот самый fd, типо проходится, читает
    #     if data: #эти данные
    #         ql.mem.write(buf, data) #mem получается память, закидываю куда указывает buf по идеи
    #         debug(f"read({fd}, {count}) -> {len(data)} bytes")
    #         #read должен показать, сколько чего то прочитать?
    #         ql.os.set_syscall_return(len(data)) # и тут он держит
    #     else:
    #         #а тут должная выйти ошибка если там ничего нет по идеи
    #         debug(f"read({fd}) -> EOF (0)") #EOF (0) типо конец файла который он читает, как пишут
    #         ql.os.set_syscall_return(0)
    # else:#нет
    #     #тут типо должная выйти ошибка, если не сработает
    #     return None

#теперь Nginx должен отправлять ответ, на то что он читанул по идеи
# и даже ответ мне нужно типо провести
# он возьмет count инфу из buf где то в памяти и закинет в fd? в итоге все 151 должно
# def hook_write(ql, fd, buf, count):
#     if fd == CONN_FD: #он в моем соедниение? да
#         data = bytes(ql.mem.read(buf, count))#ql возьмет count где то с buf и все это будет в bytes питона
#         #я же там сухие байты просто содержу
#         sys.stdout.buffer.write(data) #это мы выведем, по идеи просто байты
#         sys.stdout.buffer.flush() #тут в гайде пишут, не обязательно, какой то буфер скинь, типо поможет
#         debug(f"write({fd}, {count}) -> stdout, terminating")#тут будет просто сообщение, а то я ничего не увижу
#         #что там происходит фиг пойми без fwrite
#         ql.os.set_syscall_return(count)#тут Nginx типо должен остановится, все сделано
#         ql.emu_stop()# и вот получается я сделал всю эмуляцию, просто stop
#     else: #не в моем соединение
#         return None

#что то я поторопился, закрытие ведь тоже действие?
#значит и закрытие надо проверять
# def hook_close(ql, fd):
#     if fd in (LISTEN_FD, CONN_FD, EPOLL_FD):
#         debug(f"close({fd})")
#         ql.os.set_syscall_return(0)
#     else:
#         return None

#так мне нужно создавать epoll говорят, типо так в норме делают
# наврятли конечно, там тысячи запросов будет, что все сломается, допустим в общем
#нужно создать типо галочку, галочка стоит или не стоит, да или нет flags
# вот здесь я использую другое рандомное число, ну 200
# def hook_epoll_create1(ql, flags):
#     debug(f"epoll_create(size={size}) -> fd={EPOLL_FD}") #пусть отобразит 200
#     ql.os.set_syscall_return(EPOLL_FD)# и держит в голове 200

# def hook_ioctl(ql, fd, request, arg):
#     if request == FIONBIO:
#         debug(
#             f"ioctl(FIONBIO, fd={fd}, arg=0x{arg:x}) -> 0"
#         )
#         ql.os.set_syscall_return(0)
#         return

#     ql.os.set_syscall_return(-1)
#fd 150 соединение
#epfd 200 пауза
#op - допустим операции разные
#EPOLL_CTL_ADD добавить fd куда то
#EPOLL_CTL_DEL удалить fd
#EPOLL_CTL_MOD изменить какиенибудь параметы
#event события получается, все еще не сильно понимаю, че там я буду менять
#и при каких условиях, ну делают, значит надо
# def hook_epoll_ctl(ql, epfd, op, fd, event):
#     debug(f"epoll_ctl(epfd={epfd}, op={op}, fd={fd}) -> 0") #чето так много всего мне надо показывать
#     ql.os.set_syscall_return(0)

#вот это черт возьми сложно
#теперь эта пауза должна быть прописано? вообще по идеи
#я по сути своей прописываю все то что и так происходит в Nginx
#только ручками, я должен ЗАСТАВИТЬ ЕГО ЗАБИТЬ ПАМЯТЬ
# def hook_epoll_wait(ql, epfd, events, maxevents, timeout):
#     debug("epoll_wait() -> 1 event (listen_fd ready)")
#     # отобразит по идеи events=1, data.fd=listen_fd, че там за хаос на экран выйдет
#     ql.mem.write(events, (1).to_bytes(4, 'little') + LISTEN_FD.to_bytes(4, 'little', signed=True))
#     #вручную создать в памяти эмуляции структуру данных, которую 
#     #операционная система заполнила бы сама epoll_wait.
#     ql.os.set_syscall_return(1)#продолжить эмуляцию

#поведение прописано, допустим, теперь это все надо запускать
#а где это все там на image?

# def main():
#     ql = Qiling(
#         ["/opt/rootfs/usr/sbin/nginx", "-c", "/etc/nginx/nginx.conf"],
#         "/opt/rootfs",
#         verbose=QL_VERBOSE.DEFAULT,
#         multithread=True
#     )

#     ql.os.set_syscall("epoll_create", hook_epoll_create)
#     ql.os.set_syscall("ioctl", hook_ioctl)

#     ql.run()

#Теперь мне надо что бы эти хуки происходили, получается
#должно происходить что то типо
#когда эмулируемая программа выполнит чето там с таким именем,
#вызови вместо вот этого чегото там мою фигню
#спасибо хоть имена совпадают

    # ql.os.set_syscall('socket', hook_socket) #сначало запустится место подключение
    # ql.os.set_syscall('bind', hook_bind) #после этого присоединим это место
    # ql.os.set_syscall('listen', hook_listen) #будем его прослушивать
    # ql.os.set_syscall('accept', hook_accept) # принимать че там выслушали
    # ql.os.set_syscall('read', hook_read) # читать че мы там присоединили
    # ql.os.set_syscall('write', hook_write)# выписывать че нибудь
    # ql.os.set_syscall('close', hook_close) # и закрывать соединение
    # ql.os.set_syscall('epoll_create1', hook_epoll_create1) # тут типо создается точка остановки
    # ql.os.set_syscall('epoll_ctl', hook_epoll_ctl) #тут мне точка отобразится
    # ql.os.set_syscall('epoll_wait', hook_epoll_wait) #здесь будет ожидание иначе все накроется
#оно все равно накрывается
#кароче в nginx есть еще какие то действия которые если не проработать
#все закрывается с тоннами ошибок
#получается типо заглушки всех действий сделать
#    ql.os.set_syscall('setsockopt', lambda ql, *args: ql.os.set_syscall_return(0))
#    ql.os.set_syscall('getsockname', lambda ql, *args: ql.os.set_syscall_return(0))
#    ql.os.set_syscall('fcntl', lambda ql, *args: ql.os.set_syscall_return(0))
#я фиг знает что это за действия, поэтому просто возьму их и вставлю
# endregion
