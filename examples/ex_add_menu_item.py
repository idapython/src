import idaapi

def cb(*args):
    print("Callback called!")
    return 1

try:
    ex_addmenu_item_ctx
    idaapi.del_menu_item(ex_addmenu_item_ctx)
    print("Menu removed")
    del ex_addmenu_item_ctx
except:
    ex_addmenu_item_ctx = idaapi.add_menu_item("Search/", "X", "", 0, cb, tuple("hello world"))
    if ex_addmenu_item_ctx is None:
        print("Failed to add menu!")
        del ex_addmenu_item_ctx
    else:
        print("Menu added successfully. Run the script again to delete the menu")