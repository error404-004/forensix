@echo off
setlocal
set "JAVA_HOME=C:\Program Files\Java\jdk-22"
call "C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2024.1.4\plugins\maven\lib\maven3\bin\mvn.cmd" %*
endlocal
