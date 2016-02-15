package jenkins.plugins.debsign;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

public class Deb extends AbstractDescribableImpl<Deb> {
  private final String gpgKeyName;
  private final String includes;
  private final String cmdlineOpts;

  @DataBoundConstructor
  public Deb(String gpgKeyName, String includes, String cmdlineOpts) {
    this.gpgKeyName = gpgKeyName;
    this.includes = includes;
    this.cmdlineOpts = cmdlineOpts;
  }

  public String getGpgKeyName() {
    return gpgKeyName;
  }

  public String getIncludes() {
    return includes;
  }

  public String getCmdlineOpts() {
    return cmdlineOpts;
  }

  @Extension
  public static class DescriptorImpl extends Descriptor<Deb> {
    @Override
    public String getDisplayName() {
      return ""; // unused
    }
  }
}
