Piper for Burp Suite
====================

Building
--------

Execute `./gradlew build` and you'll have the plugin ready in
`build/libs/burp-piper.jar`

Known issues
------------

 - Terminal emulator ignores background color when _Look and feel_ is set
   to _Nimbus_, see https://bugs.openjdk.java.net/browse/JDK-8058704

Security
--------

Piper configurations can be exported and imported. As configurations define 
commands to be executed on the user's machine, importing malicious 
configurations is a security risk. 

Piper disables configurations loaded via the GUI to prevent exploitation, and 
unexpected behavior (e.g.: modification of HTTP messages). To support 
automation, Piper enables configurations loaded via the `PIPER_CONFIG` 
environment variable, so extra care must be taken in this use case. 

Users should always review configurations before importing or enabling them. 

License
-------

The whole project is available under the GNU General Public License v3.0,
see `LICENSE.md`. The [swing-terminal component][1] was developed by
@redpois0n, released under this same license.

[1]: https://github.com/redpois0n/swing-terminal
