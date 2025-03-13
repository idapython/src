import ida_graph
import ida_funcs
import ida_gdl
import ida_kernwin
import idc

func = ida_funcs.get_func(idc.here())
qflow = ida_gdl.qflow_chart_t("", func, 0, 0, 0)
for n in range(qflow.size()):
    node = qflow[n]
    print(f'Start ea : {node.start_ea:x}, end ea: {node.end_ea:x}, index: {n}')
    ni = ida_graph.node_info_t()
    ni.bg_color = 0xFF00
    ida_graph.set_node_info(func.start_ea, n, ni, ida_graph.NIF_BG_COLOR)
ida_kernwin.refresh_idaview_anyway()