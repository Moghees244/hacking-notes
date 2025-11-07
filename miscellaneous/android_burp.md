# Installing Burp Certificate in Android Device

```shell
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1
mv cacert.pem <hash>.0

cd C:\Users\<username>\AppData\Local\Android\Sdk\emulator
.\emulator.exe -avd <device_name> -writable-system

adb root
adb remount
adb push <cert>.0 /sdcard/

adb reboot
adb root

adb shell
> mv /sdcard/<cert>.0 /system/etc/security/cacerts/
> chmod 644 /system/etc/security/cacerts/<cert>.0

adb reboot
```
