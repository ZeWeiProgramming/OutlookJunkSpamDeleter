Just run the .ps1

Don't work?

    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber

    If you encounter execution policy errors, run:
    
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
