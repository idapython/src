import idaapi

def cb(*args):
    print("Callback called!")
    return 1

try:
    ctx
    idaapi.del_menu_item(ctx)
    print("Menu removed")
    del ctx
except:
    ctx = idaapi.add_menu_item("Search/", "X", "", 0, cb, tuple("hello world"))
    if ctx is None:
        print("Failed to add menu!")
        del ctx
    else:
        print("Menu added successfully. Run the script again to delete the menu")