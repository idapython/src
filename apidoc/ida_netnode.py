
class netnode(object):
    def getblob(self, start, tag) -> Union[bytes, None]:
        """
        Get a blob from a netnode.

        @param start the index where the blob starts (it may span on multiple indexes)
        @param tag the netnode tag
        @return a blob, or None
        """
        pass

    def getclob(self, start, tag) -> Union[str, None]:
        """
        Get a large amount of text from a netnode.

        @param start the index where the clob starts (it may span on multiple indexes)
        @param tag the netnode tag
        @return a clob, or None
        """
        pass

