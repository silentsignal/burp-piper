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

License
-------

The whole project is available under the GNU General Public License v3.0,
see `LICENSE.md`. The [swing-terminal component][1] was developed by
@redpois0n, released under this same license.

[1]: https://github.com/redpois0n/swing-terminal
