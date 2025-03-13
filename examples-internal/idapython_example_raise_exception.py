"""This internal test is used to verify that pc_api tests won't swallow
exceptions while using IDAPYTHON_EXAMPLE <path_to_script>"""

raise ImportError("Nasty exception at the script")
