
class cfunc_t(object):
    def find_item_coords(self, *args):
        """
        This method has the following signatures:

            1. find_item_coords(item: citem_t) -> Tuple[int, int]
            2. find_item_coords(item: citem_t, x: int_pointer, y: int_pointer) -> bool

        NOTE: The second form is retained for backward-compatibility,
        but we strongly recommend using the first.

        @param item The item to find coordinates for in the pseudocode listing
        """
        pass

class cfuncptr_t(object):
    def find_item_coords(self, *args):
        """
        This method has the following signatures:

            1. find_item_coords(item: citem_t) -> Tuple[int, int]
            2. find_item_coords(item: citem_t, x: int_pointer, y: int_pointer) -> bool

        NOTE: The second form is retained for backward-compatibility,
        but we strongly recommend using the first.

        @param item The item to find coordinates for in the pseudocode listing
        """
        pass

