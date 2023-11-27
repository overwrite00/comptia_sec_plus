# Certificazione CompTIA Security+ (Exam SY0-601)

![Logo CompTIA Security+](images/comptiasecplus.jpeg)

Di seguito riporto la lista degli obiettivi con i relativi argomenti del percorso di studio per l'ottenimento della certificazione CompTIA Security+ (SY0-601). Può essere utilizzato anche come base di partenza per coloro che si avvicinano al mondo della Cybersecurity e vogliono avere un punto di partenza sugli argomenti da studiare per poi approfondire.

* Esame richiesto: **SY0-601**
* Numero di domande: **90**
* Tipo di domande: **A scelta multipla e basate sulla migliore** (_performance-based_)
* Durata: **90 minuti+30** (_per coloro che non sono madre lingua inglese_)
* Punteggio minimo per il superamento: **750** (su una scala da 100-900)

## Obiettivi d'esame (domini)

| **Dominio** | **% di domande** |
| :--- | :---: |
| 1.0 Attacks, Threats and vulnerability | 24% |
| 2.0 Architecture and Design | 21% |
| 3.0 Implementation | 25% |
| 4.0 Operations and Incident Response | 16% |
| 5.0 Governance, Risk, and Compliance | 14% |
| Totale | 100% |

## 1.0 Attacks, Threats and vulnerability

### 1.1 Compare and contrast different types of social engineering techniques

* Phishing
* Smishing
* Vishing
* Spam
* Spam over Instant Messaging (SPIM)
* Spear phishing
* Dumpster diving
* Shoulder surfing
* Pharming
* Tailgating
* Eliciting information (Sollecitare informazioni)
* Whaling
* Prepending
* Identity fraud
* Invoice scams
* Credential harvesting
* Reconnaissance
* Hoax
* Impersonation
* Watering hole attack
* Typosquatting
* Pretexting
* Influence campaigns
  * Hybrid warfare
  * Social media
* Principies (reasons for effectiveness)
  * Authority
  * Intimidation
  * Consensus
  * Scarcity
  * Familiarity
  * Trust
  * Urgency

### 1.2 Given a scenario, analyze potential indicators to determine the type of attack

* Malware
  * Ransomware
  * Trojans
  * Worms
  * Potentially unwanted programs (PUPs)
  * Fileless virus
  * Command and control
  * Bots
  * Cryptomalware
  * Logic bombs
  * Spyware
  * Keyloggers
  * Remote access Trojan (RAT)
  * Rootkit
  * Backdoor
* Password attacks
  * Spraying
  * Dictionary
  * Brute force
    * Offline
    * Online
  * Rainbow table
  * Plaintext/unencrypted
* Physical attaks
  * Malicious Universal
  * Serial Bus (USB) cable
  * Malicious flash drive
  * Card cloning
  * Skimming
* Adversarial artificial Intelligence (AI)
  * Tainted training data for machine learning (ML)
  * Security of machine learning algorithms
* Supply chain attacks
* Cloud-based vs. on-premises attacks
* Cryptographic attacks
  * Birthday
  * Collision
  * Downgrade

### 1.3 Given a scenario, analyze potential indicators associated with application attacks

* Privilege escalation
* Cross-site scripting
* Injections
  * Structured query language (SQL)
  * Dynamic-link library (DLL)
  * Lightweight Directory
  * Access Protocol (LDAP)
  * Extensible Markup Language (XML)
* Pointer/object dereference
* Directory traversal
* Buffer overflows
* Race conditions
  * Time of check/time of use
* Error handling
* Improper input handling
* Replay attack
  * Session replays
* Integer overflow
* Request forgeries
  * Server-side
  * Cross-site
* Application programming interface (API) attacks
* Resource exhaustion
* Memory leak
* Secure Sockets Layer (SSL stripping)
* Driver manipulation
  * Shimming
  * Refactoring
* Pass the hash

### 1.4 Given a scenario, analyze potential indicators associated with network attacks

* Wireless
  * Evil twin
  * Rogue access point
  * Bluesnarfing
  * Bluejacking
  * Disassociation
  * Jamming
  * Radio frequency identification (RFID)
  * Near-field communication (NFC)
  * Initialization vector (IV)
* On-path attack (ex _man-in-the-middle attack/man-in-the-browser attack_)
* Layer 2 attacks
  * Address resolution
  * Protocol (ARP) poisoning
  * Media access control (MAC) flooding
  * MAC cloning
* Domain name system (DNS)
  * Domain hijacking
  * DNS poisoning
  * Uniform Resource
  * Locator (URL) redirection
  * Domain reputation
* Distributed denial-of-service (DDoS)
  * Network
  * Application
  * Operational technology (OT)
* Malicious code or script execution
  * PowerShell
  * Python
  * Bash
  * Macros
  * Visual Basic Applications (VBA)

### 1.5 Explain different threat actors, vectors, and intelligence sources

* Actors and threats
  * Advanced persistent threat (ATP)
  * Insider threats
  * State actors
  * Hacktivists
  * Script kiddies
  * Criminal syndicates
  * Hackers
    * Authorized
    * Unauthorized
    * Semi-authorized
  * Shadow IT
  * Competitors
  * Attributes of actors
    * Internal/external
    * Level of sophistication/capability
    * Resources/funding
    * Intent/motivation
  * Vectors
    * Direct access
    * Wireless
    * Email
    * Supply chain
    * Social media
    * Removable media
    * Cloud
  * Threat intelligence sources
    * Open-source intelligence (OSINT)
    * Closed/proprietary
    * Vulnerability databases
    * Public/private information-sharing centers
    * Dark web
    * Indicators of compromise
    * Automated Indicator Sharing (AIS)
    * Structured Threat Information eXpression (STIX)/Trusted Automated eXchange of Intelligence Information (TAXII)
    * Predictive analysis
    * Threat maps
    * File/code repositories
  * Research sources
    * Vendor websites
    * Vulnerability feeds
    * Conferences
    * Academic journals
    * Request for comments (RFC)
    * Local industry groups
    * Social media
    * Threat feeds
    * Adversary tactics, techniques, and procedures (TTP)

### 1.6 Explain the security concerns associated with various types of vulnerabilities

* Cloud-based vs. on premises vulnerabilities
* Zero-day
* Weak configurations
  * Open permissions
  * Unsecure root accounts
  * Errors
  * Weak encryption
  * Unsecure protocols
  * Default settings
  * Open port and services
* Third-party risks
  * Vendor management
    * System integration
    * Lack of vendor support
  * Supply chain
  * Outsourced code development
  * Data storage
* Improper or weak patch management
  * Firmware
  * Operating system (OS)
  * Applications
* Legacy platforms
* Impacts
  * Data loss
  * Data breaches
  * Data exfiltration
  * Identity theft
  * Financial
  * Reputation
  * Availability loss

### 1.7 Summarize the techniques used in security assesments

* Threat hunting
  * Intelligence fusion
  * Threat feeds
  * Advisories and bulletins
  * Maneuver
* Vulnerability scans
  * False positives
  * False negatives
  * Log reviews
  * Credentialed vs. non-credentialed
  * Intrusive vs. non-intrusive
  * Application
  * Web application
  * Network
  * Common Vulnerabilities and Exposures (CVE)/Common Vulnerability Scoring System (CVSS)
  * Configuration review
* Syslog/Security information and event management (SIEM)
  * Review reports
  * Packet capture
  * Data inputs
  * User behavior analysis
  * Sentiment analysis
  * Security monitoring
  * Log aggregation
  * Log collectors
* Security orchestration, automation, and response (SOAR)

### 1.8 Explain the techniques used in penetration testing

* Penetration testing
  * Known environment
  * Unknown environment
  * Partially known environment
  * Rules of engagement
  * Lateral movement
  * Privilege escalation
  * Persistence
  * Cleanup
  * Bug bounty
  * Pivoting
* Passive and active reconnaissance
  * Drones
  * War flying
  * War driving
  * Footprinting
  * OSINT
* Exercise types
  * Red-team
  * Blue-team
  * White-team
  * Purple-team

## 2.0 Architecture and Design

### 2.1 Explain the importance of security concepts in an enterprise environment

* Configuration management
  * Diagrams
  * Baseline configuration
  * Standard naming conventions
  * Internet protocol (IP) schema
* Data sovereignty
* Data protection
  * Data loss prevention (DLP)
  * Masking
  * Encryption
  * At rest
  * In transit/motion
  * In processing
  * Tokenization
  * Rights management
* Geographical considerations
* Response and recovery controls
* Secure Sockets Layer (SSL)/Transport Layer Security (TLS) inspection
* Hashing
* API considerations
* Site resiliency
  * Hot site
  * Cold site
  * Warm site
* Deception and disruption
  * Honeypots
  * Honeyfiles
  * Honeynets
  * Fake telemetry
  * DNS sinkhole

### 2.2 Summarize virtualization and cloud computing concepets

* Cloud models
  * Infrastructure as service (IaaS)
  * Platform as service (PaaS)
  * Software as service (SaaS)
  * Anything as service (XaaS)
  * Public
  * Community
  * Private
  * Hybrid
* Cloud service providers
* Managed service provides (MSP)/Managed security service provider (MSSP)
* On-premises vs. off-premises
* Fog computing
* Edge computing
* Thin client
* Containers
* Microservices/API
* Infrastructure as code
  * Software-defined networking (SDN)
  * Software-defined visibilty (SDV)
* Serverless architecture
* Services integration
* Resource policies
* Transit gateway
* Virtualization
  * Virtual machine (VM) sprawl avoidance
  * WM escape protection

### 2.3 Summarize secure application development, deployment and automation concepts

* Environment
  * Development
  * Test
  * Staging
  * Production
  * Quality assurance (QA)
* Provisioning and deprovisioning
* Integrity measurement
* Secure coding techniques
  * Normalization
  * Stored procedures
  * Obfuscation/camouflage
  * Code reuse/dead code
  * Server-side vs. client-side execution and validation
  * Memory management
  * Use of third-party libraries and software development kits (SDKs)
  * Data exposure
* Open Web Application Security Project (OWASP)
* Software diversity
  * Compiler
  * Binary
* Automation/scripting
  * Automated courses of action
  * Continous monitoring
  * Continous validation
  * Continous integration
  * Continous delivery
  * Continous deployment
* Elasticity
* Scalability
* Version control

### 2.4 Summarize authentication and authorization design concepts

* Authentication methods
  * Directory services
  * Federation
  * Attestation
  * Technologies
    * Time-based one-time password (TOTP)
    * HMAC-based one-time password (HOTP)
    * Short message service (SMS)
    * Token key
    * Static codes
    * Authentication applications
    * Push notifications
    * Phone call
  * Smart card authentication
* Biometrics
  * Fingerprint
  * Retina
  * Iris
  * Facial
  * Voice
  * Vein
  * Gait analysis
  * Efficacy rates
  * False acceptance
  * False rejection
  * Crossover error rate
* Multifactor authentication (MFA) factors and attributes
  * Factors
    * Something you know
    * Something you have
    * Something you are
  * Attributes
    * Somewhere you are
    * Something you can do
    * Something you exhibit
    * Someone you know
* Authentication, authorization and accounting (AAA)
* Cloud vs. on-premises requirements

### 2.5 Given a scenario, implement cybersecurity resilience

* Redundancy
  * Geographic dispersal
  * Disk
    * Redundant array of inexpensive disks (RAID) levels
    * Multipath
  * Network
    * Load balancers
    * Network interface card (NIC) teaming
  * Power
    * Uninterruptible power supply (UPS)
    * Generator
    * Dual supply
    * Managed power distribution units (PDUs)
* Replication
  * Storage area network
  * VM
* On-premises vs. cloud
* Backup types
  * Full
  * Incremental
  * Snapshot
  * Differential
  * Tape
  * Disk
  * Copy
  * Network-attached storage (NAS)
  * Storage area network
  * Cloud
  * Image
  * Online vs. offline
  * Offsite storage
    * Distance consideration
* Non-persistence
  * Revert to known state
  * Last known-good configuration
  * Live boot media
* High availability
  * Scalability
* Restoration order
* Diversity
  * Technologies
  * Vendors
  * Crypto
  * Controls

### 2.6 Explain the security implications of embedded and specialized systems

* Embedded systems
  * Raspberry Pi
  * Field-programmable gate-array (FPGA)
  * Arduino
* Supervisory control and data acquisition (SCADA)/industrial control system (ICS)
  * Facilities
  * Industrial
  * Manufacturing
  * Energy
  * Logistics
* Internet of Things (IoT)
  * Sensors
  * Smart devices
  * Wearables
  * Facility automation
  * Weak defaults
* Specialized
  * Medical systems
  * Vehicles
  * Aircraft
  * Smart meters
* Voice over IP (VoIP)
* Heating, ventilation, air conditioning (HVAC)
* Drones
* Multifunction printer (MFP)
* Real-time operating system (RTOS)
* Surveillance systems
* System on chip (SoC)
* Communication considerations
  * 5G
  * Narrow-band
  * Baseband radio
  * Subscriber identity module (SIM) cards
  * Zigbee
* Constraints
  * Power
  * Compute
  * Network
  * Crypto
  * Inability to path
  * Authentication
  * Range
  * Cost
  * Implied trust

### 2.7 Explain the importance of physical security controls

* Bollards/barricades
* Access control vestibules
* Badges
* Alarms
* Signage
* Cameras
  * Motion recognition
  * Object detection
* Closed-circuit television (CCTV)
* Industrial camouflage
* Personnel
  * Guards
  * Robot sentries
  * Reception
  * Two-person integrity/control
* Locks
  * Biometrics
  * Electronic
  * Physical
  * Cable locks
* USB data blocker
* Lighting
* Fencing
* Fire suppression
* Sensors
  * Motion detection
  * Noise detection
  * Proximity reader
  * Moisture detection
  * Cards
  * Temperature
* Drones
* Visitor logs
* Faraday cages
* Air gap
* Screened subnet (previously known as demilitarized zone)
* Protected cable distribution
* Secure areas
  * Air gap
  * Vault
  * Safe
  * Hot aisle
  * Cold aisle
* Secure data destruction
  * Burning
  * Shredding
  * Pulping
  * Pulverizing
  * Degaussing
  * Third-party solutions

### 2.8 Summarize the basics of cryptographic concepts

* Digital signatures
* Key length
* Key stretching
* Salting
* Hashing
* Key exchange
* Elliptic-curve cryptography
* Perfect forward secrecy
* Quantum
  * Communications
  * Computing
* Post-quantum
* Ephemeral
* Modes of operation
  * Authenticated
  * Unauthenticated
  * Counter
* Blockchain
  * Public ledgers
* Cipher suites
  * Stream
  * Block
* Symmetric vs. asymmetric
* Lightweight cryptography
* Steganography
  * Audio
  * Video
  * Image
* Homomorphic encryption
* Common use cases
  * Low power devices
  * Low latency
  * High resiliency
  * Supporting confidentiality
  * Supporting integrity
  * Supporting obfuscation
  * Supporting authentication
  * Supporting non-repudation
* Limitations
  * Speed
  * Size
  * Weak Keys
  * Time
  * Longevity
  * Predictability
  * Reuse
  * Entropy
  * Computational overheads
  * Resource vs. security constraints

## 3.0 Implementation

### 3.1 Given a scenario, implement secure protocols

* Protocols
  * Domain Name System Security Extensions (DNSSEC)
  * SSH
  * Secure/Multipurpose Internet Mail Extensions (S/MIME)
  * Secure Real-time Transport Protocol (SRTP)
  * Lightweight Directory Access Protocol Over SSL (LDAPS)
  * File Transfer Protocol, Secure (FTPS)
  * SSH File Transfer Protocol (SFTP)
  * Simple Network Management Protocol, version 3 (SNMPv3)
  * Hypertext transfer protocol over SSL/TLS (HTTPS)
  * IPSec
    * Authentication header (AH)/Encapsulation Security Payloads (ESP)
    * Tunnel/transport
  * Post Office Protocol (POP)/Internet Message Access Protocol (IMAP)
* Use cases
  * Voice and video
  * Time sincronization
  * Email and web
  * File transfer
  * Directory services
  * Remote access
  * Domain name resolution
  * Routing and switching
  * Network address allocation
  * Subscription services

### 3.2 Given a scenario, implement host or applications security solutions

* Endpoint protection
  * Antivirus
  * Anti-malware
  * Endpoint detection and response (EDR)
  * DLP
  * Next-generation firewall (NGFW)
  * Host-based intrusion prevention system (HIPS)
  * Host-based intrusion detection system (HIDS)
  * Host-based firewall
* Boot integrity
  * Boot security/Unified Extensible Firmware Interface (UEFI)
  * Measured boot
  * Boot attestation
* Database
  * Tokenization
  * Salting
  * Hashing
* Application security
  * Input validations
  * Secure cookies
  * Hypertext Transfer Protocol (HTTP) headers
  * Code signing
  * Allow list
  * Block list/deny list
  * Secure coding practices
  * Static code analysis
    * Manual code review
  * Dynamic code analysis
  * Fuzzing
* Hardening
  * Open ports and services
  * Registry
  * Disk encryption
  * OS
  * Patch management
    * Third-party updates
    * Auto-update
* Self-encryption drive (SED)/full-disk encryption (FDE)
  * Opal
* Hardware root of trust
* Trusted Platform Module (TPM)
* Sandboxing

### 3.3 Given a scenario, implement secure network designs

* Load balancing
  * Active/active
  * Active/passive
  * Scheduling
  * Virtual IP
  * Persistence
* Network segmentation
  * Virtual local area network (VLAN)
  * Screened subnet (previously know as demilitarized zone)
  * East-west traffic
  * Extranet
  * Intranet
  * Zero Trust
* Virtual private network (VPN)
  * Always-on
  * Split tunnel vs. full tunnel
  * Remote access vs. site-to-site
  * IPSec
  * SSL/TLS
  * HTML5
  * Layer 2 tunneling protocol (L2TP)
* DNS
* Network access control (NAC)
  * Agent and agentless
* Out-of-band management
* Port security
  * Broadcast storm prevention
  * Bridge Protocol Data Unit (BPDU) guard
  * Loop prevention
  * Dynamic Host Configuration Protocol (DHCP) snooping
  * Media access control (MAC) filtering
* Network appliances
  * Jump servers
  * Proxy servers
    * Forward
    * Reverse
  * Network-based intrusion detection system (NIDS)/network based intrusion prevention system (NIPS)
    * Signature-based
    * Heuristic/behavior
    * Anomaly
    * Inline vs. passive
  * HSM
  * Sensors
  * Collectors
  * Aggregators
  * Firewalls
    * Web application firewall (WAF)
    * NGFW
    * Stateful
    * Stateless
    * Unified threat management (UTM)
    * Network address translation (NAT gateway)
    * Content/URL filter
    * Open-source vs. proprietary
    * Hardware vs. software
    * Appliance vs. host-based vs. virtual
* Access control list (ACL)
* Route security
* Quality of service (QoS)
* Implication of IPv6
* Port spanning/port mirroring
  * Port taps
* Monitoring services
* File integrity monitors

### 3.4 Given a scenario, install and configure wireless security settings

* Cryptographic protocols
  * WiFi protected Access 2 (WPA2)
  * WiFi protected Access 3 (WPA3)
  * Counter-mode/CBC-MAC Protocol (CCMP)
  * Simultaneous Authentication of Equals (SAE)
* Authentication protocols
  * Extensible Authentication Protocol (EAP)
  * Protected Extensible Authetication Protocol (PEAP)
  * EAP-FAST
  * EAP-TLS
  * EAP-TTLS
  * IEEE 802.1X
  * Remote Authentication Dial-in User Service (RADIUS) Federation
* Methods
  * Pre-shared key (PSK) vs. Enterprise vs. Open
  * WiFi Protected Setup (WPS)
  * Captative portals
* Installation considerations
  * Site surveys
  * Heat maps
  * WiFi analyzers
  * Channel overlaps
  * Wireless access point (WAP) placement
  * Controller and access point security

### 3.5 Given a scenario, implement secure mobile solutions

* Connection methods and receivers
  * Cellular
  * WiFi
  * Bluetooth
  * NFC
  * Infrared
  * USB
  * Point-to-point
  * Point-to-multipoint
  * Global Positioning System (GPS)
  * RFID
* Mobile device management (MDM)
  * Application management
  * Content management
  * Remote wipe
  * Geofencing
  * Geolocation
  * Screen locks
  * Push notifications
  * Passwords and PINs
  * Biometrics
  * Context-aware authentication
  * Containerization
  * Storage segmentation
  * Full device encryption
* Mobile devices
  * MicroSD hardware security module (HSM)
  * MDM/Unified Endpoint management (UEM)
  * Mobile application management (MAM)
  * SEAndroid
* Enforcement and monitoring of:
  * Third-party application stores
  * Rooting/jailbreaking
  * Sideloading
  * Custom firmware
  * Carrier unlocking
  * Firmware over-the-air (OTA) updates
  * Camera use
  * SMS/Multimedia Messaging Service (MMS)/Rich Communication Services (RCS)
  * External media
  * USB On-the-Go (USB OTG)
  * Recording microphone
  * GPS tagging
  * WiFi direct/ad hoc
  * Tethering
  * Hotspot
  * Payment methods
* Deployment models
  * Bring your own device (BYOD)
  * Corporate-owned personally enabled (COPE)
  * Chose your own device (CYOD)
  * Corporate-owned
  * Virtual desktop infrastructure (VDI)

### 3.6 Given a scenario, apply cybersecurity solutions to the cloud

* Cloud security controls
  * High availability across zones
  * Resource policies
  * Secrets management
  * Integration and auditing
  * Storage
    * Permissions
    * Encryption
    * Replication
    * High availability
  * Network
    * Virtual networks
    * Public and private subnets
    * Segmentation
    * API inspection and integration
  * Compute
    * Security groups
    * Dynamic resource allocation
    * Instance awareness
    * Virtual private cloud (VPC) endpoint
    * Container security
* Solutions
  * CASB
  * Application security
  * Next-generation secure web gateway (SWG)
  * Firewall considerations in a cloud environment
    * Cost
    * Need for segmentation
    * Open Systems Interconnection (OSI) layers
* Cloud native controls vs. third-party solutions

### 3.7 Given a scenario, implement identity and account management controls

* Identity
  * Identity provider (IdP)
  * Atributes
  * Certificates
  * Tokens
  * SSH Keys
  * Smart cards
* Account types
  * User account
  * Shared and generic accounts/credentials
  * Guest accounts
  * Service accounts
* Account policies
  * Password complexity
  * Password history
  * Password reuse
  * Network location
  * Geofencing
  * Geotagging
  * Geolocation
  * Time-based logins
  * Access policies
  * Account permissions
  * Account audits
  * Impossible travel time/risky login
  * Lockout
  * Disablement

### 3.8 Given a scenario, implement authentication and authorization solutions

* Authentication management
  * Password keys
  * Password vaults
  * TPM
  * HSM
  * Knowledge-based authentication
* Authentication/autorization
  * EAP
  * Challenge-Handshake
  * Authentication Protocol (CHAP)
  * Password Authentication Protocol (PAP)
  * 802.1x
  * RADIUS
  * Single sign-on (SSO)
  * Security Assertion Markup Language (SAML)
  * Terminal Access Controller Access Control System Plus (TACACS+)
  * OAuth
  * OpenID
  * Kerberos
* Access control schemes
  * Attribute based access control (ABAC)
  * Role-based access control
  * Rule-based access control
  * MAC
  * Discretionary access control (DAC)
  * Conditional access
  * Privileged access management
  * Filesystem permissions

### 3.9 Given scenario, implement public key infrastructure
