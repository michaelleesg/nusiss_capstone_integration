@echo off
setlocal ENABLEDELAYEDEXPANSION

set "MAIN=main"
set "PDF=%MAIN%.pdf"

cd /d "%~dp0"
echo [INFO] Building %MAIN%.tex with pdflatex + bibtex

REM --- Clean stale aux files for %MAIN% ---
del /f /q "%MAIN%.bbl" "%MAIN%.blg" "%MAIN%.aux" "%MAIN%.out" "%MAIN%.toc" "%MAIN%.lof" "%MAIN%.lot" "%MAIN%.run.xml" 2>nul

REM --- Pass 1: pdflatex (produce .aux) ---
pdflatex -file-line-error -jobname=%MAIN% -interaction=nonstopmode -halt-on-error "%MAIN%.tex"
if errorlevel 1 goto :fail

REM --- BibTeX (only if citations exist) ---
if exist "%MAIN%.aux" (
  findstr /C:"\citation" "%MAIN%.aux" >nul 2>nul
  if %ERRORLEVEL%==0 (
    echo [INFO] Running bibtex on %MAIN%
    bibtex "%MAIN%"
    if errorlevel 1 goto :fail
  ) else (
    REM If you routinely use \nocite{*}, uncomment next two lines:
    REM echo [INFO] Forcing bibtex due to possible \nocite usage
    REM bibtex "%MAIN%"
  )
)

REM --- Pass 2 & 3: pdflatex (resolve refs) ---
pdflatex -file-line-error -jobname=%MAIN% -interaction=nonstopmode -halt-on-error "%MAIN%.tex"
if errorlevel 1 goto :fail
pdflatex -file-line-error -jobname=%MAIN% -interaction=nonstopmode -halt-on-error "%MAIN%.tex"
if errorlevel 1 goto :fail

if exist "%PDF%" (
  echo [OK] Build complete: "%PDF%"
  goto :eof
)

:fail
echo [ERROR] Build failed; check "%MAIN%.log"
exit /b 1
