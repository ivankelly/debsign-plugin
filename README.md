# Jenkins DEB Sign Plugin

This is a complete ripoff of the [Jenkins RPM Sign plugin](https://github.com/jenkinsci/rpmsign-plugin).

This plugin adds a post-build step to sign debs using GPG.

## Dependencies

This plugin depends on both **gpg** and **expect** being installed on the host machine. 

## Building and installing

To build the plugin, run

```
$ mvn package
```

This will create a hpi file (target/debsign-plugin.hpi). Install this through the Jenkins web UI.


