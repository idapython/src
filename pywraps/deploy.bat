@echo off

rem Please use the same tag for the same .i file
rem That means if many insertions are going to happen in one given .i file then don't use more than code marking tag

set PY=c:\python27\python.exe

echo.
echo -------- DEPLOY started --------------------------------------------------
echo.

rem  --------------------------------------------------------------------------
echo Deploying idaapi (common functions, notifywhen)
%PY% deploy.py py_idaapi py_cvt.hpp,py_idaapi.hpp,py_idaapi.py,py_notifywhen.hpp,py_notifywhen.py ..\swig\idaapi.i

rem  --------------------------------------------------------------------------
echo Deploying Graph
%PY% deploy.py py_graph py_graph.hpp,py_graph.py ..\swig\graph.i

rem  --------------------------------------------------------------------------
echo Deploying custview
%PY% deploy.py py_custviewer py_custview.py,py_custview.hpp ..\swig\kernwin.i

rem  --------------------------------------------------------------------------
echo Deploying plgform
%PY% deploy.py py_plgform py_plgform.hpp,py_plgform.py ..\swig\kernwin.i

rem  --------------------------------------------------------------------------
echo Deploying expr
%PY% deploy.py py_expr py_expr.hpp,py_expr.py ..\swig\expr.i

rem  --------------------------------------------------------------------------
echo Deploying cli
%PY% deploy.py py_cli py_cli.py,py_cli.hpp ..\swig\kernwin.i

rem  --------------------------------------------------------------------------
echo Deploying Loader
%PY% deploy.py py_loader py_loader.hpp ..\swig\loader.i

rem  --------------------------------------------------------------------------
echo Deploying kernwin, choose2, askusingform
%PY% deploy.py py_kernwin py_kernwin.hpp,py_kernwin.py,py_choose.hpp,py_choose2.hpp,py_choose2.py,py_askusingform.hpp,py_askusingform.py ..\swig\kernwin.i

rem  --------------------------------------------------------------------------
echo Deploying idd
%PY% deploy.py py_idd py_dbg.hpp,py_appcall.py ..\swig\idd.i

rem  --------------------------------------------------------------------------
echo Deploying nalt
%PY% deploy.py py_nalt py_nalt.hpp,py_nalt.py ..\swig\nalt.i

rem  --------------------------------------------------------------------------
echo Deploying dbg
%PY% deploy.py py_dbg py_dbg.hpp ..\swig\dbg.i

rem  --------------------------------------------------------------------------
echo Deploying linput/diskio
%PY% deploy.py py_diskio py_linput.hpp,py_diskio.hpp,py_diskio.py ..\swig\diskio.i

rem  --------------------------------------------------------------------------
echo Deploying name
%PY% deploy.py py_name py_name.hpp,py_name.py ..\swig\name.i

rem  --------------------------------------------------------------------------
echo Deploying qfile
%PY% deploy.py py_qfile py_qfile.hpp ..\swig\fpro.i

rem  --------------------------------------------------------------------------
echo Deploying bytes
%PY% deploy.py py_bytes py_bytes.hpp,py_custdata.py,py_custdata.hpp ..\swig\bytes.i

rem  --------------------------------------------------------------------------
echo Deploying typeinf
%PY% deploy.py py_typeinf py_typeinf.hpp ..\swig\typeinf.i

rem  --------------------------------------------------------------------------
echo Deploying gdl
%PY% deploy.py py_gdl py_gdl.py ..\swig\gdl.i

rem  --------------------------------------------------------------------------
echo Deploying ua
%PY% deploy.py py_ua py_ua.hpp,py_ua.py ..\swig\ua.i

rem  --------------------------------------------------------------------------
echo Deploying idp
%PY% deploy.py py_idp py_idp.hpp ..\swig\idp.i

rem  --------------------------------------------------------------------------
echo Deploying lines
%PY% deploy.py py_lines py_lines.hpp,py_lines.py ..\swig\lines.i

rem  --------------------------------------------------------------------------
echo Deploying pc_win32_appcall
%PY% deploy.py appcalltest py_appcall.py ..\..\..\tests\input\pc_win32_appcall.pe.hints

rem  --------------------------------------------------------------------------
echo Deploying ex_custdata example
%PY% deploy.py ex_custdata ..\examples\ex_custdata.py ..\..\..\tests\input\pc_win32_custdata1.pe.hints

rem  --------------------------------------------------------------------------
echo Deploying ex_formchooser
%PY% deploy.py ex_formchooser py_askusingform.py ..\..\formchooser\formchooser.py

rem  --------------------------------------------------------------------------
echo Deploying ex_askusingform
%PY% deploy.py ex_askusingform py_askusingform.py ..\examples\ex_askusingform.py

rem  --------------------------------------------------------------------------
echo Deploying ex_cli example
%PY% deploy.py ex_cli_ex1 py_cli.py ..\examples\ex_cli.py

rem  --------------------------------------------------------------------------
echo Deploying ex_expr example
%PY% deploy.py ex_expr py_expr.py ..\examples\ex_expr.py

rem  --------------------------------------------------------------------------
echo Deploying ex_custview.py example
%PY% deploy.py py_custviewerex1 py_custview.py ..\examples\ex_custview.py

rem  --------------------------------------------------------------------------
echo.
echo -------- DEPLOY finished -------------------------------------------------
echo.

:end