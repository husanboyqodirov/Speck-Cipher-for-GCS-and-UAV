
    Developer: Husanboy (후산보이)
    Web: https://husanboy.me
    Email: husanboy.me@gmail.com
    Repository: https://github.com/husanboyqodirov/Speck-Cipher-for-GCS-and-UAV

    These programs implement secure communication channel between
    Ground Control Station and Unmanned Aerial/Ground Vehicle.
    
    Speck lightweight block cipher for encryption.
    Message Authentication Codes for data integrity.
    TCP protocol for networking.

    Hardware used: Raspberry Pi, Pixhawk, GCS computer.

    Note: These programs are optimized for Linux systems.
    If your system is Windows, please use Windows-Subsystem for Linux
    to run these programs.


1) Environment Setup:
		Networking Libraries: 
			$ sudo apt-get update
			$ sudo apt-get install build-essential libc6-dev
		OpenSSL Libraries:
			$ sudo apt-get update
			$ sudo apt-get install libssl-dev

2) Compile:
	$ gcc speck_gcs.c -o speck_gcs -lssl -lcrypto
	$ gcc speck_uav.c -o speck_uav -lssl -lcrypto

3) Run
	$ ./speck_gcs
	$ ./speck_uav