class Donet < Formula
  desc "Real-time packet threat detection with emoji indicators"
  homepage "https://github.com/donet/network-analyzer"
  url "https://github.com/donet/network-analyzer/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"  # Will need to be updated when releasing
  license "MIT"

  depends_on "python@3.11"
  depends_on "libpcap"

  resource "scapy" do
    url "https://files.pythonhosted.org/packages/source/s/scapy/scapy-2.5.0.tar.gz"
    sha256 "REPLACE_WITH_SCRAPY_SHA256"
  end

  resource "colorama" do
    url "https://files.pythonhosted.org/packages/source/c/colorama/colorama-0.4.6.tar.gz"
    sha256 "REPLACE_WITH_COLORAMA_SHA256"
  end

  resource "PyYAML" do
    url "https://files.pythonhosted.org/packages/source/P/PyYAML/PyYAML-6.0.1.tar.gz"
    sha256 "REPLACE_WITH_PYYAML_SHA256"
  end

  def install
    # Install Python dependencies
    resources.each do |r|
      r.stage do
        system "python3", "-m", "pip", "install", "--prefix=#{prefix}", "."
      end
    end

    # Install DONET itself
    system "python3", "-m", "pip", "install", "--prefix=#{prefix}", "."

    # Create symlink for donet command
    bin.install "cli.py" => "donet"
  end

  test do
    system "#{bin}/donet", "--help"
  end
end
