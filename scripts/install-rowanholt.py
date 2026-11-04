#!/usr/bin/env python3
"""
Rowanholt Installer
Cross-platform installer for Rowanholt with Docker Desktop or OrbStack

Supports: macOS (Intel/Apple Silicon), Linux, Windows
"""

import os
import sys
import platform
import subprocess
import urllib.request
import shutil
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def disable():
        """Disable colors on Windows if not supported"""
        if platform.system() == 'Windows':
            Colors.BLUE = Colors.GREEN = Colors.YELLOW = Colors.RED = Colors.BOLD = Colors.END = ''


class OSDetector:
    """Detect operating system and architecture"""

    @staticmethod
    def get_os():
        """Returns: 'macos', 'linux', or 'windows'"""
        system = platform.system().lower()
        if system == 'darwin':
            return 'macos'
        return system

    @staticmethod
    def get_arch():
        """Returns: 'arm64', 'amd64', 'x86_64', etc."""
        machine = platform.machine().lower()
        if machine in ['arm64', 'aarch64']:
            return 'arm64'
        elif machine in ['x86_64', 'amd64']:
            return 'amd64'
        return machine

    @staticmethod
    def get_linux_distro():
        """Returns Linux distribution name"""
        try:
            with open('/etc/os-release') as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith('ID='):
                        return line.split('=')[1].strip().strip('"')
        except:
            pass
        return 'unknown'


class DockerInstaller:
    """Base class for Docker installers"""

    DOCKER_DESKTOP_VERSIONS = {
        'macos': {
            'arm64': {
                'version': '4.51.0',
                'build': '210443',
                'url': 'https://desktop.docker.com/mac/main/arm64/210443/Docker.dmg',
                'engine': 'v28.5.2'
            },
            'amd64': {
                'version': '4.51.0',
                'build': '210443',
                'url': 'https://desktop.docker.com/mac/main/amd64/210443/Docker.dmg',
                'engine': 'v28.5.2'
            }
        },
        'linux': {
            'amd64': {
                'version': '4.51.0',
                'deb': 'https://desktop.docker.com/linux/main/amd64/210443/docker-desktop-4.51.0-amd64.deb',
                'rpm': 'https://desktop.docker.com/linux/main/amd64/210443/docker-desktop-4.51.0-x86_64.rpm',
                'engine': 'v28.5.2'
            }
        },
        'windows': {
            'amd64': {
                'version': '4.51.0',
                'build': '210443',
                'url': 'https://desktop.docker.com/win/main/amd64/210443/Docker%20Desktop%20Installer.exe',
                'engine': 'v28.5.2'
            }
        }
    }

    def __init__(self, os_type, arch):
        self.os_type = os_type
        self.arch = arch
        self.downloads_dir = Path.home() / 'Downloads'
        self.downloads_dir.mkdir(exist_ok=True)

    def print_header(self, text):
        """Print colored header"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}  {text}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 70}{Colors.END}\n")

    def print_info(self, text):
        """Print info message"""
        print(f"{Colors.BLUE}ℹ{Colors.END}  {text}")

    def print_success(self, text):
        """Print success message"""
        print(f"{Colors.GREEN}✓{Colors.END}  {text}")

    def print_warning(self, text):
        """Print warning message"""
        print(f"{Colors.YELLOW}⚠{Colors.END}  {text}")

    def print_error(self, text):
        """Print error message"""
        print(f"{Colors.RED}✗{Colors.END}  {text}")

    def run_command(self, cmd, shell=False, check=True):
        """Run shell command and return result"""
        try:
            result = subprocess.run(
                cmd if not shell else cmd,
                shell=shell,
                capture_output=True,
                text=True,
                check=check
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            return False, e.stdout, e.stderr
        except Exception as e:
            return False, "", str(e)

    def check_docker_installed(self):
        """Check if Docker is already installed"""
        success, stdout, _ = self.run_command(['docker', '--version'], check=False)
        if success:
            return True, stdout.strip()
        return False, None

    def download_file(self, url, destination):
        """Download file with progress"""
        self.print_info(f"Downloading from: {url}")
        self.print_info(f"Saving to: {destination}")

        try:
            urllib.request.urlretrieve(url, destination)
            self.print_success(f"Downloaded: {destination}")
            return True
        except Exception as e:
            self.print_error(f"Download failed: {e}")
            return False


class MacOSInstaller(DockerInstaller):
    """macOS-specific installer"""

    def check_homebrew(self):
        """Check if Homebrew is installed"""
        success, _, _ = self.run_command(['which', 'brew'], check=False)
        return success

    def install_docker_desktop(self):
        """Install Docker Desktop 4.51.0 on macOS"""
        self.print_header("Installing Docker Desktop 4.51.0 for macOS")

        if self.arch not in self.DOCKER_DESKTOP_VERSIONS['macos']:
            self.print_error(f"Docker Desktop not available for architecture: {self.arch}")
            return False

        version_info = self.DOCKER_DESKTOP_VERSIONS['macos'][self.arch]
        self.print_info(f"Version: {version_info['version']} (Engine {version_info['engine']})")
        self.print_info(f"Architecture: {self.arch}")

        # Check if already installed
        installed, version = self.check_docker_installed()
        if installed:
            self.print_warning(f"Docker is already installed: {version}")
            response = input(f"{Colors.YELLOW}Do you want to continue and replace it? (y/N): {Colors.END}").strip().lower()
            if response != 'y':
                self.print_info("Installation cancelled")
                return False

        # Download
        dmg_path = self.downloads_dir / 'Docker-4.51.0.dmg'
        if not dmg_path.exists():
            if not self.download_file(version_info['url'], dmg_path):
                return False
        else:
            self.print_info(f"Using existing download: {dmg_path}")

        # Instructions for manual installation
        self.print_header("Installation Steps")
        print(f"{Colors.BOLD}Please follow these steps:{Colors.END}\n")
        print(f"1. {Colors.GREEN}Stop current Docker Desktop if running:{Colors.END}")
        print(f"   • Open Docker Desktop")
        print(f"   • Click Docker icon in menu bar → Quit Docker Desktop\n")

        print(f"2. {Colors.GREEN}Uninstall current Docker Desktop (if installed):{Colors.END}")
        print(f"   • Open Docker Desktop")
        print(f"   • Docker icon in menu bar → Troubleshoot → Uninstall")
        print(f"   • Or drag Docker.app from Applications to Trash\n")

        print(f"3. {Colors.GREEN}Mount the downloaded DMG:{Colors.END}")
        subprocess.run(['open', str(dmg_path)])
        print(f"   • DMG opened automatically\n")

        print(f"4. {Colors.GREEN}Drag Docker.app to Applications folder{Colors.END}")
        print(f"   • Wait for copy to complete\n")

        print(f"5. {Colors.GREEN}Open Docker from Applications{Colors.END}")
        print(f"   • Wait for Docker to start (check menu bar icon)\n")

        print(f"6. {Colors.GREEN}Disable auto-updates:{Colors.END}")
        print(f"   • Docker Desktop → Settings → Software Updates")
        print(f"   • Uncheck 'Automatically check for updates'\n")

        input(f"{Colors.YELLOW}Press Enter when installation is complete...{Colors.END}")

        # Verify installation
        installed, version = self.check_docker_installed()
        if installed:
            self.print_success(f"Docker installed successfully: {version}")
            return True
        else:
            self.print_error("Docker installation could not be verified")
            return False

    def install_orbstack(self):
        """Install OrbStack on macOS"""
        self.print_header("Installing OrbStack for macOS")

        self.print_info("OrbStack is:")
        print("  • 2-3x faster than Docker Desktop")
        print("  • Uses ~4GB RAM instead of 8-12GB")
        print("  • No gVisor networking issues")
        print("  • Better file sharing performance")
        print()
        self.print_info("Pricing: Free for personal use, $10/month for commercial")
        print()

        # Check if already installed
        success, _, _ = self.run_command(['which', 'orbctl'], check=False)
        if success:
            self.print_warning("OrbStack is already installed")
            response = input(f"{Colors.YELLOW}Do you want to continue anyway? (y/N): {Colors.END}").strip().lower()
            if response != 'y':
                self.print_info("Installation cancelled")
                return False

        # Check for Homebrew
        if self.check_homebrew():
            self.print_info("Installing OrbStack via Homebrew...")
            success, stdout, stderr = self.run_command(['brew', 'install', '--cask', 'orbstack'])
            if success:
                self.print_success("OrbStack installed via Homebrew")
            else:
                self.print_error(f"Homebrew installation failed: {stderr}")
                self.print_info("Trying manual download instead...")
                return self._install_orbstack_manual()
        else:
            self.print_info("Homebrew not found, using manual installation")
            return self._install_orbstack_manual()

        # Instructions
        self.print_header("Setup Instructions")
        print(f"{Colors.BOLD}Please follow these steps:{Colors.END}\n")
        print(f"1. {Colors.GREEN}Stop Docker Desktop if running{Colors.END}")
        print(f"   • Docker icon in menu bar → Quit Docker Desktop\n")

        print(f"2. {Colors.GREEN}Open OrbStack from Applications{Colors.END}")
        print(f"   • Follow the setup wizard")
        print(f"   • OrbStack will detect Docker Desktop and offer to import settings\n")

        print(f"3. {Colors.GREEN}Verify installation:{Colors.END}")
        print(f"   • Run: docker --version")
        print(f"   • Run: docker context show (should show 'orbstack')\n")

        input(f"{Colors.YELLOW}Press Enter when setup is complete...{Colors.END}")

        # Verify
        success, stdout, _ = self.run_command(['docker', '--version'], check=False)
        if success:
            self.print_success(f"Docker installed successfully: {stdout.strip()}")

            # Check context
            success, stdout, _ = self.run_command(['docker', 'context', 'show'], check=False)
            if success and 'orbstack' in stdout.lower():
                self.print_success("OrbStack is active Docker context")
            else:
                self.print_warning("Docker is installed but OrbStack may not be active")
                self.print_info("Switch to OrbStack: docker context use orbstack")
            return True
        else:
            self.print_error("Docker installation could not be verified")
            return False

    def _install_orbstack_manual(self):
        """Manual OrbStack installation"""
        self.print_info("Downloading OrbStack...")
        orbstack_url = "https://orbstack.dev/download"

        self.print_header("Manual Installation")
        print(f"{Colors.BOLD}Please download OrbStack manually:{Colors.END}\n")
        print(f"1. Visit: {Colors.BLUE}{orbstack_url}{Colors.END}")
        print(f"2. Download OrbStack for macOS")
        print(f"3. Open the downloaded file and drag OrbStack to Applications")
        print(f"4. Open OrbStack from Applications\n")

        response = input(f"{Colors.YELLOW}Open OrbStack download page now? (Y/n): {Colors.END}").strip().lower()
        if response != 'n':
            subprocess.run(['open', orbstack_url])

        return True


class LinuxInstaller(DockerInstaller):
    """Linux-specific installer"""

    def __init__(self, os_type, arch):
        super().__init__(os_type, arch)
        self.distro = OSDetector.get_linux_distro()

    def install_docker_desktop(self):
        """Install Docker Desktop on Linux"""
        self.print_header("Installing Docker Desktop 4.51.0 for Linux")

        if self.arch not in self.DOCKER_DESKTOP_VERSIONS['linux']:
            self.print_error(f"Docker Desktop not available for architecture: {self.arch}")
            self.print_info("Consider installing Docker Engine instead")
            return False

        version_info = self.DOCKER_DESKTOP_VERSIONS['linux'][self.arch]
        self.print_info(f"Version: {version_info['version']} (Engine {version_info['engine']})")
        self.print_info(f"Distribution: {self.distro}")

        # Determine package type
        if self.distro in ['ubuntu', 'debian', 'linuxmint', 'pop']:
            return self._install_deb(version_info['deb'])
        elif self.distro in ['fedora', 'rhel', 'centos', 'rocky', 'alma']:
            return self._install_rpm(version_info['rpm'])
        else:
            self.print_error(f"Unsupported Linux distribution: {self.distro}")
            self.print_info("Please install Docker Engine manually: https://docs.docker.com/engine/install/")
            return False

    def _install_deb(self, url):
        """Install .deb package"""
        deb_path = self.downloads_dir / 'docker-desktop.deb'

        if not deb_path.exists():
            if not self.download_file(url, deb_path):
                return False

        self.print_info("Installing .deb package (requires sudo)...")
        success, stdout, stderr = self.run_command(['sudo', 'apt-get', 'install', '-y', str(deb_path)])

        if success:
            self.print_success("Docker Desktop installed successfully")
            return True
        else:
            self.print_error(f"Installation failed: {stderr}")
            return False

    def _install_rpm(self, url):
        """Install .rpm package"""
        rpm_path = self.downloads_dir / 'docker-desktop.rpm'

        if not rpm_path.exists():
            if not self.download_file(url, rpm_path):
                return False

        self.print_info("Installing .rpm package (requires sudo)...")
        success, stdout, stderr = self.run_command(['sudo', 'dnf', 'install', '-y', str(rpm_path)])

        if success:
            self.print_success("Docker Desktop installed successfully")
            return True
        else:
            self.print_error(f"Installation failed: {stderr}")
            return False

    def install_orbstack(self):
        """OrbStack not available on Linux"""
        self.print_error("OrbStack is only available for macOS")
        self.print_info("Use Docker Desktop or Docker Engine instead")
        return False


class WindowsInstaller(DockerInstaller):
    """Windows-specific installer"""

    def install_docker_desktop(self):
        """Install Docker Desktop on Windows"""
        self.print_header("Installing Docker Desktop 4.51.0 for Windows")

        if self.arch not in self.DOCKER_DESKTOP_VERSIONS['windows']:
            self.print_error(f"Docker Desktop not available for architecture: {self.arch}")
            return False

        version_info = self.DOCKER_DESKTOP_VERSIONS['windows'][self.arch]
        self.print_info(f"Version: {version_info['version']} (Engine {version_info['engine']})")

        # Download
        exe_path = self.downloads_dir / 'Docker-Desktop-Installer.exe'
        if not exe_path.exists():
            if not self.download_file(version_info['url'], exe_path):
                return False
        else:
            self.print_info(f"Using existing download: {exe_path}")

        # Instructions
        self.print_header("Installation Steps")
        print(f"{Colors.BOLD}Please follow these steps:{Colors.END}\n")
        print(f"1. {Colors.GREEN}Stop current Docker Desktop if running{Colors.END}")
        print(f"2. {Colors.GREEN}Run the installer: {exe_path}{Colors.END}")
        print(f"3. {Colors.GREEN}Follow the installation wizard{Colors.END}")
        print(f"4. {Colors.GREEN}Restart your computer when prompted{Colors.END}")
        print(f"5. {Colors.GREEN}Disable auto-updates in Docker Desktop settings{Colors.END}\n")

        response = input(f"{Colors.YELLOW}Run installer now? (Y/n): {Colors.END}").strip().lower()
        if response != 'n':
            subprocess.run([str(exe_path)])

        return True

    def install_orbstack(self):
        """OrbStack not available on Windows"""
        self.print_error("OrbStack is only available for macOS")
        self.print_info("Use Docker Desktop or WSL2 with Docker Engine instead")
        return False


def prompt_for_image_paths(installer):
    """Prompt user to configure forensic image paths"""

    installer.print_header("Configure Forensic Image Paths")

    print(f"{Colors.BOLD}Rowanholt needs to know where your forensic images (E01 files) are located.{Colors.END}\n")
    print(f"You can configure up to 3 image directories.")
    print(f"These paths will be mounted into the Docker containers.\n")

    paths = []

    # Primary path (required)
    installer.print_info("PRIMARY image path (required)")
    while True:
        path = input(f"{Colors.YELLOW}Enter path to forensic images: {Colors.END}").strip()

        if not path:
            installer.print_error("Primary path is required")
            continue

        # Expand user home directory
        path = os.path.expanduser(path)

        # Check if path exists
        if os.path.exists(path) and os.path.isdir(path):
            installer.print_success(f"Valid path: {path}")
            paths.append(path)
            break
        else:
            installer.print_error(f"Path does not exist or is not a directory: {path}")

            # Offer to create it
            create = input(f"{Colors.YELLOW}Create this directory? (y/N): {Colors.END}").strip().lower()
            if create == 'y':
                try:
                    Path(path).mkdir(parents=True, exist_ok=True)
                    installer.print_success(f"Created directory: {path}")
                    paths.append(path)
                    break
                except Exception as e:
                    installer.print_error(f"Failed to create directory: {e}")

    # Secondary path (optional)
    print()
    installer.print_info("SECONDARY image path (optional - press Enter to skip)")
    while True:
        path = input(f"{Colors.YELLOW}Enter secondary path or press Enter to skip: {Colors.END}").strip()

        if not path:
            installer.print_info("Skipping secondary path")
            break

        # Expand user home directory
        path = os.path.expanduser(path)

        # Check if path exists
        if os.path.exists(path) and os.path.isdir(path):
            installer.print_success(f"Valid path: {path}")
            paths.append(path)
            break
        else:
            installer.print_error(f"Path does not exist or is not a directory: {path}")

            # Offer to create it
            create = input(f"{Colors.YELLOW}Create this directory? (y/N): {Colors.END}").strip().lower()
            if create == 'y':
                try:
                    Path(path).mkdir(parents=True, exist_ok=True)
                    installer.print_success(f"Created directory: {path}")
                    paths.append(path)
                    break
                except Exception as e:
                    installer.print_error(f"Failed to create directory: {e}")

    # Tertiary path (optional)
    if len(paths) > 1:
        print()
        installer.print_info("TERTIARY image path (optional - press Enter to skip)")
        while True:
            path = input(f"{Colors.YELLOW}Enter tertiary path or press Enter to skip: {Colors.END}").strip()

            if not path:
                installer.print_info("Skipping tertiary path")
                break

            # Expand user home directory
            path = os.path.expanduser(path)

            # Check if path exists
            if os.path.exists(path) and os.path.isdir(path):
                installer.print_success(f"Valid path: {path}")
                paths.append(path)
                break
            else:
                installer.print_error(f"Path does not exist or is not a directory: {path}")

                # Offer to create it
                create = input(f"{Colors.YELLOW}Create this directory? (y/N): {Colors.END}").strip().lower()
                if create == 'y':
                    try:
                        Path(path).mkdir(parents=True, exist_ok=True)
                        installer.print_success(f"Created directory: {path}")
                        paths.append(path)
                        break
                    except Exception as e:
                        installer.print_error(f"Failed to create directory: {e}")

    return paths


def update_docker_compose(installer, image_paths, repo_dir):
    """Update docker-compose.yml with configured image paths"""

    if not image_paths:
        return False

    installer.print_header("Updating Docker Configuration")

    docker_compose_path = repo_dir / 'docker-compose.yml'

    if not docker_compose_path.exists():
        installer.print_error(f"docker-compose.yml not found at: {docker_compose_path}")
        installer.print_warning("You'll need to manually configure image paths in docker-compose.yml")
        return False

    try:
        # Read the docker-compose.yml file
        with open(docker_compose_path, 'r') as f:
            lines = f.readlines()

        # Find the volumes section for backend and celery-worker
        # We'll add the image path mounts
        new_lines = []
        in_backend_volumes = False
        in_celery_volumes = False
        added_to_backend = False
        added_to_celery = False

        for i, line in enumerate(lines):
            new_lines.append(line)

            # Detect backend service volumes section
            if 'backend:' in line:
                in_backend_volumes = False
            if in_backend_volumes and 'volumes:' in line:
                # Add image paths after the volumes: line
                for idx, path in enumerate(image_paths):
                    mount_point = f"/data{idx if idx > 0 else ''}"
                    new_lines.append(f"      - {path}:{mount_point}:ro  # Forensic images (read-only)\n")
                added_to_backend = True
                in_backend_volumes = False
            if 'backend:' in line and not added_to_backend:
                in_backend_volumes = True

            # Detect celery-worker service volumes section
            if 'celery-worker:' in line:
                in_celery_volumes = False
            if in_celery_volumes and 'volumes:' in line:
                # Add image paths after the volumes: line
                for idx, path in enumerate(image_paths):
                    mount_point = f"/data{idx if idx > 0 else ''}"
                    new_lines.append(f"      - {path}:{mount_point}  # Forensic images (read-write for output)\n")
                added_to_celery = True
                in_celery_volumes = False
            if 'celery-worker:' in line and not added_to_celery:
                in_celery_volumes = True

        # Write back to file
        with open(docker_compose_path, 'w') as f:
            f.writelines(new_lines)

        installer.print_success("Updated docker-compose.yml with image paths:")
        for idx, path in enumerate(image_paths):
            mount_point = f"/data{idx if idx > 0 else ''}"
            print(f"  • {path} → {mount_point}")

        print()
        installer.print_info(f"Note: Inside containers, access images at:")
        for idx, path in enumerate(image_paths):
            mount_point = f"/data{idx if idx > 0 else ''}"
            print(f"  • {mount_point}/your-image.E01")

        return True

    except Exception as e:
        installer.print_error(f"Failed to update docker-compose.yml: {e}")
        installer.print_warning("You'll need to manually configure image paths")
        return False


def setup_env_file(installer, repo_dir):
    """Copy .env.example to .env if it doesn't exist"""
    try:
        env_example = repo_dir / '.env.example'
        env_file = repo_dir / '.env'

        if not env_example.exists():
            installer.print_warning(".env.example not found in repository")
            return False

        if env_file.exists():
            installer.print_info(".env file already exists, skipping")
            return True

        # Copy .env.example to .env
        shutil.copy(env_example, env_file)
        installer.print_success("Created .env from .env.example")
        return True

    except Exception as e:
        installer.print_error(f"Failed to create .env file: {e}")
        return False


def main():
    """Main installer function"""

    # Disable colors on Windows if needed
    if platform.system() == 'Windows':
        Colors.disable()

    # Detect OS
    os_type = OSDetector.get_os()
    arch = OSDetector.get_arch()

    # Select installer
    if os_type == 'macos':
        installer = MacOSInstaller(os_type, arch)
    elif os_type == 'linux':
        installer = LinuxInstaller(os_type, arch)
    elif os_type == 'windows':
        installer = WindowsInstaller(os_type, arch)
    else:
        print(f"Unsupported operating system: {os_type}")
        sys.exit(1)

    # Print header
    installer.print_header("Rowanholt Installer")
    installer.print_info(f"Operating System: {os_type}")
    installer.print_info(f"Architecture: {arch}")
    if os_type == 'linux':
        installer.print_info(f"Distribution: {installer.distro}")
    print()

    # Check current installation
    installed, version = installer.check_docker_installed()
    if installed:
        installer.print_warning(f"Docker is currently installed: {version}")
        print()

    # Show options
    print(f"{Colors.BOLD}Installation Options:{Colors.END}\n")

    if os_type == 'macos':
        # For macOS: OrbStack is option 1 (recommended)
        print(f"  {Colors.BOLD}1. OrbStack{Colors.END} (Latest) {Colors.GREEN}← RECOMMENDED{Colors.END}")
        print(f"     • 2-3x faster than Docker Desktop")
        print(f"     • Uses ~4GB RAM instead of 8-12GB")
        print(f"     • No gVisor networking bugs")
        print(f"     • Better file sharing performance")
        print(f"     • Free for personal use, $10/month commercial\n")

        print(f"  {Colors.BOLD}2. Docker Desktop 4.51.0{Colors.END} (Engine v28.5.2)")
        print(f"     • Stable version without gVisor bugs (4.51.0 only)")
        print(f"     • Official Docker Desktop experience")
        print(f"     • {Colors.YELLOW}⚠ Avoid 4.52.0+ (critical gVisor bugs){Colors.END}\n")
    else:
        # For Linux/Windows: Docker Desktop is the only option
        print(f"  {Colors.BOLD}1. Docker Desktop 4.51.0{Colors.END} (Engine v28.5.2)")
        print(f"     • Stable version without gVisor networking bugs")
        print(f"     • Official Docker Desktop experience")
        print(f"     • Works on macOS, Linux, and Windows\n")

    print(f"  {Colors.BOLD}3. Cancel{Colors.END}\n")

    # Get user choice
    while True:
        choice = input(f"{Colors.YELLOW}Select option (1-3): {Colors.END}").strip()

        if choice == '1':
            if os_type == 'macos':
                success = installer.install_orbstack()
            else:
                success = installer.install_docker_desktop()
            break
        elif choice == '2':
            if os_type == 'macos':
                success = installer.install_docker_desktop()
            else:
                installer.print_error("Invalid option. Please enter 1 or 3.")
                continue
            break
        elif choice == '3':
            installer.print_info("Installation cancelled")
            sys.exit(0)
        else:
            if os_type == 'macos':
                installer.print_error("Invalid option. Please enter 1, 2, or 3.")
            else:
                installer.print_error("Invalid option. Please enter 1 or 3.")

    # Configure image paths if Docker installation succeeded
    image_paths = []
    env_configured = False
    if success:
        print()
        configure = input(f"{Colors.YELLOW}Configure forensic image paths now? (Y/n): {Colors.END}").strip().lower()

        if configure != 'n':
            image_paths = prompt_for_image_paths(installer)

            # Try to find the repository directory
            script_dir = Path(__file__).parent.resolve()
            repo_dir = script_dir.parent

            if image_paths:
                print()
                update_docker_compose(installer, image_paths, repo_dir)

            # Setup .env file
            print()
            env_configured = setup_env_file(installer, repo_dir)
        else:
            installer.print_info("Skipping image path configuration")
            installer.print_warning("You'll need to manually configure paths in docker-compose.yml")

    # Final message
    if success:
        installer.print_header("Installation Complete!")
        print(f"{Colors.GREEN}✓{Colors.END} Docker is ready to use")

        if image_paths:
            print(f"{Colors.GREEN}✓{Colors.END} Forensic image paths configured")
            for idx, path in enumerate(image_paths):
                mount_point = f"/data{idx if idx > 0 else ''}"
                print(f"  • {path} → {mount_point}")

        if env_configured:
            print(f"{Colors.GREEN}✓{Colors.END} Environment file created (.env)")

        print(f"\n{Colors.BOLD}Next steps:{Colors.END}\n")

        if not image_paths:
            print(f"{Colors.YELLOW}⚠{Colors.END}  IMPORTANT: Configure forensic image paths before running tests")
            print(f"   Edit docker-compose.yml to add your image directories\n")

        step_num = 1

        if env_configured:
            print(f"{step_num}. Configure environment variables (optional):")
            print(f"   nano .env       # or use vi, vim, code, etc.")
            print(f"   # Edit settings like ports, database URL, API keys\n")
            step_num += 1

        print(f"{step_num}. Start Rowanholt:")
        print(f"   cd /path/to/rowanholt")
        print(f"   ./scripts/start-testing-mode.sh\n")
        step_num += 1

        if image_paths:
            print(f"{step_num}. Copy your E01 images to configured directories:")
            for path in image_paths:
                print(f"   • {path}")
            print()
            step_num += 1

        print(f"{step_num}. Run tests:")
        print(f"   cd tests")
        print(f"   ./scripts/run_single_test.sh win_brisk\n")
        step_num += 1

        print(f"{step_num}. Check job status:")
        print(f"   ./scripts/status.sh\n")

    else:
        installer.print_error("Installation failed or incomplete")
        sys.exit(1)


if __name__ == '__main__':
    main()
