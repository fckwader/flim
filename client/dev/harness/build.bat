@echo off
setlocal
cd /d "%~dp0"
call "..\..\msvc_env.bat"
if errorlevel 1 exit /b 1
cl /nologo /W3 t_samples.c /Fe:t_samples.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W4 t_ws_buffer.c /Fe:t_ws_buffer.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 t_launcher.c /Fe:t_launcher.exe /link /SUBSYSTEM:CONSOLE /MANIFEST:EMBED
if errorlevel 1 exit /b 1
cl /nologo /W3 t_injection.c /Fe:t_injection.exe /link /SUBSYSTEM:CONSOLE /MANIFEST:EMBED
if errorlevel 1 exit /b 1
cl /nologo /W3 /DFLIM_EXPERIMENTAL_FL26 t_injection.c /Fe:t_injection_experimental.exe /link /SUBSYSTEM:CONSOLE /MANIFEST:EMBED
if errorlevel 1 exit /b 1
cl /nologo /W3 t_build_gate.c /Fe:t_build_gate.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 /DFLIM_EXPERIMENTAL_FL26 t_build_gate.c /Fe:t_build_gate_experimental.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 t_patops.c /Fe:t_patops.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 t_compat.c /Fe:t_compat.exe
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX t_clip.c /Fe:t_clip.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 t_clip_native.c /Fe:t_clip_native.exe
if errorlevel 1 exit /b 1
cl /nologo /W4 t_cloud.c /Fe:t_cloud.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 t_profiles.c /Fe:t_profiles.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 t_profile_loader.c /Fe:t_profile_loader.exe
if errorlevel 1 exit /b 1
cl /nologo /W4 t_flp.c /Fe:t_flp.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 t_plugin_apply.c /Fe:t_plugin_apply.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_plugins.c /Fe:t_plugins.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_portable.c /Fe:t_portable.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_metadata.c /Fe:t_metadata.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_notes.c /Fe:t_notes.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX t_notes_crdt.c /Fe:t_notes_crdt.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 t_rooms.c /Fe:t_rooms.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_startup.c /Fe:t_startup.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_toolbar.c /Fe:t_toolbar.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_project_load.c /Fe:t_project_load.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_files.c /Fe:t_files.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX t_file_status.c /Fe:t_file_status.exe
if errorlevel 1 exit /b 1
cl /nologo /W3 t_queues.c /Fe:t_queues.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_inbound.c /Fe:t_inbound.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_edit_compat.c /Fe:t_edit_compat.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_logging.c /Fe:t_logging.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_transfer.c /Fe:t_transfer.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1

cl /nologo /W3 t_sweep24.c /Fe:t_sweep24.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W3 t_workflow27.c /Fe:t_workflow27.exe winhttp.lib shell32.lib user32.lib gdi32.lib bcrypt.lib advapi32.lib
if errorlevel 1 exit /b 1
