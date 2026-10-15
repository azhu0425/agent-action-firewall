# Thin wrapper: scripts/verify.py is the single source of truth.
python "$PSScriptRoot/verify.py" @args
exit $LASTEXITCODE
