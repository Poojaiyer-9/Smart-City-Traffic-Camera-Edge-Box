@echo off
echo ================================================
echo   Smart-City Traffic Camera Edge Box
echo   Installing dependencies and starting server...
echo ================================================
echo.

pip install -r requirements.txt
echo.
echo [OK] Dependencies installed.
echo.
echo Starting Edge Server on http://127.0.0.1:5000 ...
echo Open your browser at: http://127.0.0.1:5000
echo.
python edge_server.py
pause
