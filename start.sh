if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    cls
else
    clear
fi

python -m ensurepip --upgrade
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    cls
else
    clear
fi
