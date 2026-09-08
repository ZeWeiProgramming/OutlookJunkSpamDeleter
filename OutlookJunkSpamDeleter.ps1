#requires -Version 5.1

<#
.SYNOPSIS
    Cleans highly suspicious spam from the Outlook Junk Email folder
    using Microsoft Graph.

.DESCRIPTION
    Scans Junk Email, assigns a spam score, and permanently deletes
    messages whose score reaches the configured threshold.

    PowerShell 5.1 compatible.
	
.PREREQUISITES
    To install required dependencies, run the following command in PowerShell:
    
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber

    If you encounter execution policy errors, run:
    
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

    Then re-run the installation command above.
#>


# ============================================================
# CONFIGURATION
# ============================================================

$DryRun = $false

# Messages with this score or higher are deleted.
$SpamScoreThreshold = 8

# Maximum number of messages to inspect.
$MaxMessages = 500

# 0 = scan all messages.
$DaysBack = 0

# Domains protected from random-domain heuristics.
$TrustedDomains = @(
    "epicgames.com",
    "foodpanda.my",
    "maybank2u.com.my",
    "kfc.com.my"
)


# ============================================================
# LOGGING
# ============================================================

# Logging disabled.
# To re-enable, remove the <# and #> around this section.

<#
$LogDirectory = $PSScriptRoot
$LogFile = Join-Path -Path $PSScriptRoot -ChildPath "JunkCleaner.log"

if (-not (Test-Path -LiteralPath $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Timestamp] $Message"

    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}
#>

# Logging to file disabled.
# Messages are shown in PowerShell instead.

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host $Message
}


# ============================================================
# START
# ============================================================

Write-Log "========================================"
Write-Log "Outlook Junk Cleaner starting."
Write-Log "DryRun=$DryRun"
Write-Log "Threshold=$SpamScoreThreshold"
Write-Log "MaxMessages=$MaxMessages"
Write-Log "DaysBack=$DaysBack"
Write-Log "========================================"


# ============================================================
# MICROSOFT GRAPH MODULE
# ============================================================

try {

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {

        Write-Log "Microsoft.Graph.Authentication not found."
        Write-Log "Installing Microsoft.Graph.Authentication..."

        Install-Module `
            Microsoft.Graph.Authentication `
            -Scope CurrentUser `
            -Force `
            -AllowClobber `
            -ErrorAction Stop

        Write-Log "Microsoft.Graph.Authentication installed."
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
}
catch {

    Write-Log "ERROR | Could not install/import Microsoft.Graph.Authentication."
    Write-Log $_.Exception.Message

    exit 1
}


# ============================================================
# CONNECT TO GRAPH
# ============================================================

$GraphConnected = $false

try {

    Write-Log "Connecting to Microsoft Graph..."

    Connect-MgGraph `
        -Scopes "Mail.ReadWrite" `
        -NoWelcome `
        -ErrorAction Stop

    $GraphConnected = $true

    Write-Log "Connected to Microsoft Graph."
}
catch {

    Write-Log "ERROR | Microsoft Graph connection failed."
    Write-Log $_.Exception.Message

    exit 1
}


# ============================================================
# RANDOMNESS SCORE
# ============================================================

function Get-RandomnessScore {

    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return 0
    }

    $Score = 0
    $Lower = $Text.ToLowerInvariant()

    # Long strings
    if ($Text.Length -ge 18) {
        $Score += 1
    }

    if ($Text.Length -ge 25) {
        $Score += 1
    }

    if ($Text.Length -ge 32) {
        $Score += 1
    }

    # Digits
    $DigitCount = ([regex]::Matches($Text, '\d')).Count

    if ($DigitCount -ge 3) {
        $Score += 1
    }

    if ($DigitCount -ge 5) {
        $Score += 1
    }

    # Excessive consonants
    $ConsonantCount = (
        [regex]::Matches(
            $Lower,
            '[bcdfghjklmnpqrstvwxyz]'
        )
    ).Count

    if ($ConsonantCount -ge 12) {
        $Score += 1
    }

    # Long consonant runs
    if ($Lower -match '[bcdfghjklmnpqrstvwxyz]{5,}') {
        $Score += 2
    }

    # Repeated characters
    if ($Lower -match '(.)\1\1') {
        $Score += 1
    }

    # Alternating letters and digits
    if ($Lower -match '[a-z]\d[a-z]\d') {
        $Score += 1
    }

    return $Score
}


# ============================================================
# DOMAIN RANDOMNESS SCORE
# ============================================================

function Get-DomainRandomnessScore {

    param(
        [AllowNull()]
        [string]$Domain
    )

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return 0
    }

    $Score = 0

    $DomainLower = $Domain.ToLowerInvariant()

    # Check every DNS label.
    $Labels = $DomainLower -split '\.'

    foreach ($Label in $Labels) {

        if ([string]::IsNullOrWhiteSpace($Label)) {
            continue
        }

        if ($Label.Length -lt 10) {
            continue
        }

        $LabelScore = Get-RandomnessScore -Text $Label

        if ($LabelScore -ge 2) {
            $Score += 2
        }

        if ($LabelScore -ge 4) {
            $Score += 2
        }

        if ($Label.Length -ge 20) {
            $Score += 1
        }

        if ($Label.Length -ge 30) {
            $Score += 1
        }
    }

    return $Score
}


# ============================================================
# RANDOM ADDRESS DETECTION
# ============================================================

function Get-RandomAddressScore {
    param(
        [AllowNull()]
        [string]$LocalPart,
        [AllowNull()]
        [string]$Domain
    )
    
    $Score = 0
    
    # Check for completely random-looking addresses like "5YY9SFX5@4HXEVBJT1V43LWF3JSPPDDL9KPUH"
    
    if (-not [string]::IsNullOrWhiteSpace($LocalPart)) {
        
        # Check if local part is mostly random characters
        $AlphaCount = ([regex]::Matches($LocalPart, '[A-Z]')).Count
        $DigitCount = ([regex]::Matches($LocalPart, '\d')).Count
        $LowerCount = ([regex]::Matches($LocalPart, '[a-z]')).Count
        
        # High proportion of uppercase letters (random generators often use uppercase)
        if ($LocalPart.Length -ge 5) {
            $UppercaseRatio = $AlphaCount / $LocalPart.Length
            if ($UppercaseRatio -ge 0.4) {
                $Score += 2
            }
            if ($UppercaseRatio -ge 0.6) {
                $Score += 2
            }
        }
        
        # Mixed uppercase/lowercase/digits in random patterns
        $HasUpper = $LocalPart -match '[A-Z]'
        $HasLower = $LocalPart -match '[a-z]'
        $HasDigit = $LocalPart -match '\d'
        
        if ($HasUpper -and $HasLower -and $HasDigit) {
            $Score += 2
        }
        
        # Very high entropy (looks like random string)
        if ($LocalPart.Length -ge 8) {
            $UniqueChars = ($LocalPart.ToCharArray() | Select-Object -Unique).Count
            $EntropyRatio = $UniqueChars / $LocalPart.Length
            if ($EntropyRatio -ge 0.7) {
                $Score += 3
            }
        }
        
        # All caps or all alphanumeric (no real words)
        if ($LocalPart -match '^[A-Z0-9]+$' -and $LocalPart.Length -ge 5) {
            $Score += 2
        }
    }
    
    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        
        # Check for extremely long domains like "4HXEVBJT1V43LWF3JSPPDDL9KPUH"
        if ($Domain.Length -ge 20) {
            $Score += 3
        }
        if ($Domain.Length -ge 30) {
            $Score += 3
        }
        
        # Domain with no dots (not a real domain structure)
        if ($Domain -notmatch '\.') {
            $Score += 2
        }
        
        # Domain with only one label (no dot) and random characters
        if ($Domain -notmatch '\.' -and $Domain.Length -ge 15) {
            $Score += 3
        }
        
        # All caps alphanumeric domain (very suspicious)
        if ($Domain -match '^[A-Z0-9]+$') {
            $Score += 3
        }
        
        # Domain starts with number (very suspicious)
        if ($Domain -match '^\d') {
            $Score += 2
        }
    }
    
    return $Score
}


# ============================================================
# SPAM SCORE
# ============================================================

function Get-SpamScore {

    param(
        [Parameter(Mandatory = $true)]
        $Message
    )

    $Score = 0

    $Subject = [string]$Message.subject
    $SubjectLower = $Subject.ToLowerInvariant()

    $FromAddress = ""
    $DisplayName = ""

    if ($null -ne $Message.from) {

        if ($null -ne $Message.from.emailAddress) {

            $FromAddress = [string]$Message.from.emailAddress.address
            $DisplayName = [string]$Message.from.emailAddress.name
        }
    }

    if ([string]::IsNullOrWhiteSpace($FromAddress)) {

        if ($null -ne $Message.sender) {

            if ($null -ne $Message.sender.emailAddress) {

                $FromAddress = [string]$Message.sender.emailAddress.address
            }
        }
    }

    $LocalPart = ""
    $Domain = ""

    if ($FromAddress -match '^([^@]+)@([^@]+)$') {

        $LocalPart = $Matches[1]
        $Domain = $Matches[2]
    }

    $DomainLower = $Domain.ToLowerInvariant()


    # ========================================================
    # TRUSTED DOMAIN
    # ========================================================

    $IsTrustedDomain = $false

    foreach ($TrustedDomain in $TrustedDomains) {

        $TrustedDomainLower = $TrustedDomain.ToLowerInvariant()

        if (
            $DomainLower -eq $TrustedDomainLower -or
            $DomainLower.EndsWith("." + $TrustedDomainLower)
        ) {

            $IsTrustedDomain = $true
            break
        }
    }


    # ========================================================
    # SENDER / DOMAIN ANALYSIS
    # ========================================================

    if (-not $IsTrustedDomain) {

        # Random sender
        if (-not [string]::IsNullOrWhiteSpace($LocalPart)) {

            $LocalRandomScore = Get-RandomnessScore -Text $LocalPart

            if ($LocalRandomScore -ge 3) {
                $Score += 2
            }

            if ($LocalRandomScore -ge 5) {
                $Score += 2
            }
        }


        # Random domain
        if (-not [string]::IsNullOrWhiteSpace($Domain)) {

            $DomainRandomScore = Get-DomainRandomnessScore -Domain $Domain

            if ($DomainRandomScore -ge 3) {
                $Score += 2
            }

            if ($DomainRandomScore -ge 5) {
                $Score += 2
            }
        }


        # ========================================================
        # ENHANCED RANDOM ADDRESS DETECTION
        # ========================================================
        
        # Check for extremely suspicious random addresses
        $RandomAddressScore = Get-RandomAddressScore -LocalPart $LocalPart -Domain $Domain
        
        if ($RandomAddressScore -ge 8) {
            # Very high confidence these are spam
            $Score += 10
        }
        elseif ($RandomAddressScore -ge 5) {
            $Score += 7
        }
        elseif ($RandomAddressScore -ge 3) {
            $Score += 4
        }


        # ========================================================
        # EXTREME RANDOM ADDRESS PATTERNS
        # ========================================================
        
        # Detect addresses like "5YY9SFX5@4HXEVBJT1V43LWF3JSPPDDL9KPUH"
        if ($FromAddress -match '^[A-Z0-9]+@[A-Z0-9]+$' -and $FromAddress.Length -gt 15) {
            $Score += 10
        }
        
        # Detect addresses with long random domains (no dots, all caps/numbers)
        if ($Domain -match '^[A-Z0-9]{15,}$') {
            $Score += 10
        }
        
        # Detect addresses with local part that's mixed-case random
        if ($LocalPart -match '^[A-Z0-9]{6,}$' -or $LocalPart -match '^[a-z0-9]{6,}$') {
            if ($LocalPart -notmatch '[aeiou]' -and $LocalPart.Length -ge 6) {
                $Score += 5
            }
        }


        # Extremely suspicious generated domains.
        #
        # Example:
        # refijet.carservices-------qvfexvcjmzvsst.com

        if ($Domain -match '-{4,}') {

            $Score += 5
        }


        # Long domains
        if ($Domain.Length -ge 35) {
            $Score += 2
        }

        if ($Domain.Length -ge 50) {
            $Score += 2
        }


        # Many digits in domain
        $DomainDigitCount = (
            [regex]::Matches($Domain, '\d')
        ).Count

        if ($DomainDigitCount -ge 3) {
            $Score += 1
        }

        if ($DomainDigitCount -ge 6) {
            $Score += 2
        }
    }


    # ========================================================
    # STRONG GAMBLING / SPIN PATTERNS
    # ========================================================

    $StrongGamblingPatterns = @(
        '\bfree\s+spins\b'
        '\bbonus\s+spins\b'
        '\bgratis\s+spins\b'
        '\b\d+\s+free\s+spins\b'
        '\b\d+\s+bonus\s+spins\b'
        '\b\d+\s+gratis\s+spins\b'
        '\bcasino\b'
        '\bjackpot\b'
        '\bsportsbook\b'
        '\bdeposit\s+bonus\b'
        '\bno\s+deposit\b'
        '\bfree\s+bet\b'
        '\bgratis\s+inzet\b'
        '\bwelkomstpakket\b'
        '\bwelcome\s+package\b'
        '\bgolden\s+ticket\b'
    )

    $StrongGamblingMatch = $false

    foreach ($Pattern in $StrongGamblingPatterns) {

        if ($SubjectLower -match $Pattern) {

            # Strong enough to delete on its own.
            $Score += 8

            $StrongGamblingMatch = $true

            break
        }
    }


    # ========================================================
    # NORMAL GAMBLING TERMS
    # ========================================================

    if (-not $StrongGamblingMatch) {

        $NormalGamblingPatterns = @(
            '\bspins\b'
            '\bslots?\b'
            '\bgambling\b'
            '\bbetting\b'
            '\bbonus\b'
            '\bbonus\s+code\b'
            '\bcash\s+bonus\b'
        )

        foreach ($Pattern in $NormalGamblingPatterns) {

            if ($SubjectLower -match $Pattern) {

                $Score += 6

                break
            }
        }
    }


    # ========================================================
    # DUTCH ENERGY SCAM / SPAM
    # ========================================================

    #
    # These are intentionally strong.
    #
    # Examples:
    #
    # Gratis bespaarcheck: ontdek het laagste energietarief!
    # Bespaarcheck voor het laagste energietarief
    # Ontdek het laagste energietarief
    #

    $StrongDutchEnergyPatterns = @(
        '\bbespaarcheck\b'
        '\blaagste\s+energietarief\b'
        '\benergietarief\b'
        '\benergie\s+besparing\b'
        '\benergie\s+aanbieding\b'
    )

    $StrongDutchEnergyMatch = $false

    foreach ($Pattern in $StrongDutchEnergyPatterns) {

        if ($SubjectLower -match $Pattern) {

            # Delete this type of Junk immediately.
            $Score += 8

            $StrongDutchEnergyMatch = $true

            break
        }
    }


    # ========================================================
    # OTHER DUTCH SPAM
    # ========================================================

    if (-not $StrongDutchEnergyMatch) {

        $DutchSpamPatterns = @(
            'welkomstpakket'
            'gratis\s+aanbieding'
            'gratis\s+bonus'
            'gratis\s+cadeau'
            'ontgrendel'
            'claim\s+je'
        )

        foreach ($Pattern in $DutchSpamPatterns) {

            if ($SubjectLower -match $Pattern) {

                $Score += 5

                break
            }
        }
    }


    # ========================================================
    # LARGE MONEY CLAIMS
    # ========================================================

    # ASCII-only patterns.
    # This avoids PowerShell 5.1 encoding problems with EUR/GBP
    # symbols such as euro and pound characters.

    $LargeMoneyPatterns = @(
        '\$\s?\d{1,3}(?:[.,]\d{3})+'
        '\$\s?\d{4,6}'
        '\d{1,3}(?:[.,]\d{3})+\s?(?:EUR|EURO|GBP|AUD|USD)'
        '(?:EUR|EURO|GBP|AUD|USD)\s?\d{1,3}(?:[.,]\d{3})+'
        '(?:EUR|EURO|GBP|AUD|USD)\s?\d{4,6}'
    )

    foreach ($Pattern in $LargeMoneyPatterns) {

        if ($Subject -match $Pattern) {

            $Score += 4

            break
        }
    }


    # ========================================================
    # PERCENTAGE OFF / BONUS
    # ========================================================

    if (
        $SubjectLower -match
        '\b(?:[2-9]\d|100|[1-9]\d{2,})%\s*(?:off|discount|bonus)\b'
    ) {

        $Score += 4
    }


    # ========================================================
    # HEALTH / SUPPLEMENT SPAM
    # ========================================================

    $HealthSpamPatterns = @(
        'blood\s+sugar\s+support'
        'blood\s+pressure\s+support'
        'weight\s+loss\s+support'
        'male\s+enhancement'
        'sexual\s+enhancement'
        'dietary\s+supplement'
        '\bsupplement\b'
        'miracle\s+cure'
        'health\s+support'
    )

    foreach ($Pattern in $HealthSpamPatterns) {

        if ($SubjectLower -match $Pattern) {

            $Score += 5

            break
        }
    }


    # ========================================================
    # URGENCY / CLAIM LANGUAGE
    # ========================================================

    $UrgencyPatterns = @(
        'claim\s+your'
        'claim\s+je'
        'claim\s+now'
        'act\s+now'
        'limited\s+time'
        '24\s+hours?\s+only'
        'today\s+only'
        'expires?\s+today'
        'last\s+chance'
        'unlock\s+your'
        'ontgrendel'
    )

    foreach ($Pattern in $UrgencyPatterns) {

        if ($SubjectLower -match $Pattern) {

            $Score += 2

            break
        }
    }


    # ========================================================
    # RANDOM-LOOKING SUBJECT
    # ========================================================

    $SubjectRandomScore = Get-RandomnessScore -Text $Subject

    if ($SubjectRandomScore -ge 4) {

        $Score += 1
    }


    # ========================================================
    # DISPLAY NAME / DOMAIN MISMATCH
    # ========================================================

    if (
        -not $IsTrustedDomain -and
        -not [string]::IsNullOrWhiteSpace($DisplayName) -and
        -not [string]::IsNullOrWhiteSpace($Domain)
    ) {

        $DisplayLower = $DisplayName.ToLowerInvariant()

        $KnownCompanyNames = @(
            "microsoft"
            "paypal"
            "amazon"
            "apple"
            "google"
            "facebook"
            "instagram"
            "netflix"
            "steam"
            "epic games"
            "bank rakyat"
        )

        foreach ($CompanyName in $KnownCompanyNames) {

            if ($DisplayLower.Contains($CompanyName)) {

                $CompanyToken = $CompanyName.Replace(" ", "")

                if (-not $DomainLower.Contains($CompanyToken)) {

                    $Score += 3
                }

                break
            }
        }
    }


    # ========================================================
    # RETURN SCORE
    # ========================================================

    return $Score
}


# ============================================================
# GET JUNK EMAIL FOLDER
# ============================================================

try {

    Write-Log "Looking for Junk Email folder..."

    $JunkFolder = Invoke-MgGraphRequest `
        -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/me/mailFolders/junkemail" `
        -ErrorAction Stop

    if ($null -eq $JunkFolder) {

        throw "Junk Email folder could not be found."
    }

    Write-Log "Junk Email folder found."
    Write-Log "Junk folder ID: $($JunkFolder.id)"
}
catch {

    Write-Log "ERROR | Could not access Junk Email folder."
    Write-Log $_.Exception.Message

    if ($GraphConnected) {

        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
        }
    }

    exit 1
}


# ============================================================
# RETRIEVE MESSAGES
# ============================================================

$Messages = @()

try {

    Write-Log "Reading messages from Junk Email..."

    $Uri = "https://graph.microsoft.com/v1.0/me/mailFolders/junkemail/messages?`$top=100&`$select=id,subject,from,sender,receivedDateTime,internetMessageId,bodyPreview"

    while ($Uri -and ($Messages.Count -lt $MaxMessages)) {

        $Response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $Uri `
            -ErrorAction Stop

        if ($null -ne $Response.value) {

            foreach ($Message in $Response.value) {

                if ($Messages.Count -ge $MaxMessages) {
                    break
                }

                $Messages += $Message
            }
        }

        if ($Response.'@odata.nextLink') {

            $Uri = $Response.'@odata.nextLink'
        }
        else {

            $Uri = $null
        }
    }

    Write-Log "Found $($Messages.Count) messages in Junk Email."
}
catch {

    Write-Log "ERROR | Could not retrieve Junk Email messages."
    Write-Log $_.Exception.Message

    if ($GraphConnected) {

        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
        }
    }

    exit 1
}


# ============================================================
# OPTIONAL DATE FILTER
# ============================================================

if ($DaysBack -gt 0) {

    $CutoffDate = (Get-Date).AddDays(-$DaysBack)

    $Messages = @(
        $Messages | Where-Object {

            if ([string]::IsNullOrWhiteSpace($_.receivedDateTime)) {

                return $true
            }

            try {

                $Received = [DateTime]::Parse($_.receivedDateTime)

                return ($Received -ge $CutoffDate)
            }
            catch {

                return $true
            }
        }
    )

    Write-Log "After date filtering: $($Messages.Count) messages."
}


# ============================================================
# PROCESS MESSAGES
# ============================================================

$DeletedCount = 0
$KeptCount = 0
$ErrorCount = 0


foreach ($Message in $Messages) {

    $Subject = [string]$Message.subject

    if ([string]::IsNullOrWhiteSpace($Subject)) {

        $Subject = "(No Subject)"
    }


    # --------------------------------------------------------
    # GET SENDER
    # --------------------------------------------------------

    $FromAddress = ""
    $DisplayName = ""

    if ($null -ne $Message.from) {

        if ($null -ne $Message.from.emailAddress) {

            $FromAddress = [string]$Message.from.emailAddress.address
            $DisplayName = [string]$Message.from.emailAddress.name
        }
    }

    if ([string]::IsNullOrWhiteSpace($FromAddress)) {

        if ($null -ne $Message.sender) {

            if ($null -ne $Message.sender.emailAddress) {

                $FromAddress = [string]$Message.sender.emailAddress.address
            }
        }
    }


    # --------------------------------------------------------
    # SCORE
    # --------------------------------------------------------

    try {

        $Score = Get-SpamScore -Message $Message
    }
    catch {

        $Score = 0

        Write-Log "ERROR | Could not score message."
        Write-Log $_.Exception.Message
    }


    # --------------------------------------------------------
    # KEEP
    # --------------------------------------------------------

    if ($Score -lt $SpamScoreThreshold) {

        $KeptCount++

        Write-Log "KEEP | Score=$Score | From=$FromAddress | Subject=$Subject"

        continue
    }


    # --------------------------------------------------------
    # MATCH
    # --------------------------------------------------------

    Write-Log "MATCH | Score=$Score | From=$FromAddress | Subject=$Subject"


    # --------------------------------------------------------
    # DRY RUN
    # --------------------------------------------------------

    if ($DryRun) {

        Write-Log "DRY-RUN | Would DELETE | Score=$Score | From=$FromAddress | Subject=$Subject"

        continue
    }


    # --------------------------------------------------------
    # DELETE
    # --------------------------------------------------------

    try {

        if ([string]::IsNullOrWhiteSpace($Message.id)) {

            throw "Message has no Graph message ID."
        }

        $EncodedMessageId = [System.Uri]::EscapeDataString(
            [string]$Message.id
        )

        $DeleteUri = "https://graph.microsoft.com/v1.0/me/messages/$EncodedMessageId"

        Invoke-MgGraphRequest `
            -Method DELETE `
            -Uri $DeleteUri `
            -ErrorAction Stop

        $DeletedCount++

        Write-Log "DELETE | Score=$Score | From=$FromAddress | Subject=$Subject"
    }
    catch {

        $ErrorCount++

        Write-Log "ERROR | Could not delete message | From=$FromAddress | Subject=$Subject"
        Write-Log $_.Exception.Message
    }
}


# ============================================================
# SUMMARY
# ============================================================

Write-Log "========================================"
Write-Log "CLEANUP COMPLETE"
Write-Log "Total scanned : $($Messages.Count)"
Write-Log "Kept          : $KeptCount"
Write-Log "Deleted       : $DeletedCount"
Write-Log "Errors        : $ErrorCount"
Write-Log "DryRun        : $DryRun"
Write-Log "========================================"


# ============================================================
# DISCONNECT FROM MICROSOFT GRAPH
# ============================================================

# Disabled because Disconnect-MgGraph can produce an MSAL
# token-cache warning on some PowerShell/Graph configurations.

# if ($GraphConnected) {
#
#     try {
#
#         Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
#
#         Write-Log "Disconnected from Microsoft Graph."
#     }
#     catch {
#         # Ignore disconnect errors.
#     }
# }

Write-Log "Outlook Junk Cleaner finished."