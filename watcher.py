
class Watcher:
    """ Adopts psutil api for representing socket information. """

    @property
    def internet_sockets(self) -> list:
        return self.__get_internet_connections()

    @property
    def unix_sockets(self) -> list:
        return self.__get_unix_sockets_connections()

    def __get_internet_connections(self) -> list:
        pass

    def __get_unix_sockets_connections(self) -> list:
        pass
