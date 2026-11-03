#!/usr/bin/env python3
"""
Dernvale Image Path Manager
Manage forensic image paths without reinstalling Dernvale

Usage:
    python3 scripts/image-paths.py
    ./scripts/image-paths.py
"""

import os
import sys
import re
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
        Colors.BLUE = Colors.GREEN = Colors.YELLOW = Colors.RED = Colors.BOLD = Colors.END = ''


class PathManager:
    """Manage forensic image paths in docker-compose.yml"""

    def __init__(self):
        self.script_dir = Path(__file__).parent.resolve()
        self.repo_dir = self.script_dir.parent
        self.docker_compose_path = self.repo_dir / 'docker-compose.yml'

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

    def get_current_paths(self):
        """Extract current image paths from docker-compose.yml"""
        if not self.docker_compose_path.exists():
            self.print_error(f"docker-compose.yml not found at: {self.docker_compose_path}")
            return []

        paths = []
        try:
            with open(self.docker_compose_path, 'r') as f:
                lines = f.readlines()

            # Look for volume mounts that end with :/data*, :ro or without flags
            # Pattern: - /path/to/dir:/data:ro or - /path/to/dir:/data1
            pattern = re.compile(r'^\s*-\s+([^:]+):(/data\d*)(?::ro)?(?:\s+#.*)?$')

            for line in lines:
                match = pattern.match(line)
                if match:
                    host_path = match.group(1).strip()
                    container_path = match.group(2).strip()

                    # Skip if it's a named volume or special mount
                    if not host_path.startswith('/') and not host_path.startswith('~'):
                        continue

                    # Expand ~ if present
                    host_path = os.path.expanduser(host_path)

                    # Add to paths if not already present
                    if host_path not in [p[0] for p in paths]:
                        paths.append((host_path, container_path))

            return paths

        except Exception as e:
            self.print_error(f"Failed to read docker-compose.yml: {e}")
            return []

    def show_current_paths(self):
        """Display currently configured paths"""
        self.print_header("Current Forensic Image Paths")

        paths = self.get_current_paths()

        if not paths:
            self.print_warning("No forensic image paths configured")
            print()
            self.print_info("Configure paths using option 2 (Add paths) or 4 (Replace all paths)")
            return paths

        print(f"{Colors.BOLD}Configured paths:{Colors.END}\n")
        for host_path, container_path in paths:
            exists = "✓" if os.path.exists(host_path) else "✗"
            print(f"  {exists} {host_path}")
            print(f"     → {container_path} (in container)")
            print()

        return paths

    def validate_path(self, path):
        """Validate a path exists or offer to create it"""
        if not path:
            return None

        # Expand user home directory
        path = os.path.expanduser(path)

        # Check if path exists
        if os.path.exists(path) and os.path.isdir(path):
            self.print_success(f"Valid path: {path}")
            return path
        else:
            self.print_error(f"Path does not exist or is not a directory: {path}")

            # Offer to create it
            create = input(f"{Colors.YELLOW}Create this directory? (y/N): {Colors.END}").strip().lower()
            if create == 'y':
                try:
                    Path(path).mkdir(parents=True, exist_ok=True)
                    self.print_success(f"Created directory: {path}")
                    return path
                except Exception as e:
                    self.print_error(f"Failed to create directory: {e}")
                    return None

            return None

    def prompt_for_path(self, prompt_text):
        """Prompt user for a single path with validation loop"""
        while True:
            path = input(f"{Colors.YELLOW}{prompt_text}: {Colors.END}").strip()

            if not path:
                return None

            validated_path = self.validate_path(path)
            if validated_path:
                return validated_path

    def add_paths(self):
        """Add new paths to existing configuration"""
        self.print_header("Add Forensic Image Paths")

        current_paths = self.get_current_paths()
        current_host_paths = [p[0] for p in current_paths]

        new_paths = []

        print(f"{Colors.BOLD}Add up to 3 new image paths{Colors.END}\n")
        print("Press Enter to skip a path\n")

        for i in range(3):
            path = self.prompt_for_path(f"Enter path #{i+1} (or Enter to finish)")

            if not path:
                if i == 0:
                    self.print_info("No paths to add")
                break

            # Check if path already configured
            if path in current_host_paths:
                self.print_warning(f"Path already configured: {path}")
                continue

            new_paths.append(path)

        if new_paths:
            # Combine with existing paths
            all_paths = current_host_paths + new_paths
            self.update_docker_compose(all_paths)
        else:
            self.print_info("No new paths added")

    def remove_paths(self):
        """Remove paths from configuration"""
        self.print_header("Remove Forensic Image Paths")

        current_paths = self.get_current_paths()

        if not current_paths:
            self.print_warning("No paths configured to remove")
            return

        print(f"{Colors.BOLD}Current paths:{Colors.END}\n")
        for idx, (host_path, container_path) in enumerate(current_paths, 1):
            print(f"  {idx}. {host_path} → {container_path}")

        print()
        print("Enter path numbers to remove (comma-separated) or 'all' to remove all")
        selection = input(f"{Colors.YELLOW}Remove paths: {Colors.END}").strip()

        if not selection:
            self.print_info("No paths removed")
            return

        if selection.lower() == 'all':
            confirm = input(f"{Colors.YELLOW}Remove ALL paths? (y/N): {Colors.END}").strip().lower()
            if confirm == 'y':
                self.update_docker_compose([])
                self.print_success("All paths removed")
            else:
                self.print_info("Cancelled")
            return

        # Parse selection
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            remaining_paths = []

            for idx, (host_path, _) in enumerate(current_paths):
                if idx not in indices:
                    remaining_paths.append(host_path)

            self.update_docker_compose(remaining_paths)

        except ValueError:
            self.print_error("Invalid selection")

    def replace_all_paths(self):
        """Replace all paths with new configuration"""
        self.print_header("Replace All Forensic Image Paths")

        current_paths = self.get_current_paths()

        if current_paths:
            print(f"{Colors.BOLD}Current paths will be replaced:{Colors.END}\n")
            for host_path, container_path in current_paths:
                print(f"  ✗ {host_path}")
            print()

        confirm = input(f"{Colors.YELLOW}Replace all paths? (y/N): {Colors.END}").strip().lower()

        if confirm != 'y':
            self.print_info("Cancelled")
            return

        new_paths = []

        print(f"\n{Colors.BOLD}Configure up to 3 new paths{Colors.END}\n")

        # Primary path (required)
        self.print_info("PRIMARY image path (required)")
        path = self.prompt_for_path("Enter path to forensic images")
        if not path:
            self.print_error("Primary path is required")
            return

        new_paths.append(path)

        # Secondary path (optional)
        print()
        self.print_info("SECONDARY image path (optional - press Enter to skip)")
        path = self.prompt_for_path("Enter secondary path or press Enter to skip")
        if path:
            new_paths.append(path)

            # Tertiary path (optional)
            print()
            self.print_info("TERTIARY image path (optional - press Enter to skip)")
            path = self.prompt_for_path("Enter tertiary path or press Enter to skip")
            if path:
                new_paths.append(path)

        self.update_docker_compose(new_paths)

    def update_docker_compose(self, image_paths):
        """Update docker-compose.yml with new image paths"""
        if not self.docker_compose_path.exists():
            self.print_error(f"docker-compose.yml not found at: {self.docker_compose_path}")
            return False

        try:
            # Read the docker-compose.yml file
            with open(self.docker_compose_path, 'r') as f:
                lines = f.readlines()

            # Remove existing forensic image mounts and rebuild
            new_lines = []
            skip_next = False

            for line in lines:
                # Skip lines that are forensic image mounts
                if re.search(r'(/data\d*)(?::ro)?.*#.*[Ff]orensic', line):
                    continue

                new_lines.append(line)

            # Now add the new paths
            final_lines = []
            in_backend_volumes = False
            in_celery_volumes = False
            backend_volumes_found = False
            celery_volumes_found = False

            for i, line in enumerate(new_lines):
                final_lines.append(line)

                # Detect backend service volumes section
                if 'service:' in line or 'services:' in line:
                    in_backend_volumes = False
                    in_celery_volumes = False

                if 'backend:' in line:
                    in_backend_volumes = True
                    backend_volumes_found = False

                if in_backend_volumes and '  volumes:' in line and not backend_volumes_found:
                    # Add image paths after the volumes: line
                    for idx, path in enumerate(image_paths):
                        mount_point = f"/data{idx if idx > 0 else ''}"
                        final_lines.append(f"      - {path}:{mount_point}:ro  # Forensic images (read-only)\n")
                    backend_volumes_found = True

                # Detect celery-worker service volumes section
                if 'celery-worker:' in line:
                    in_celery_volumes = True
                    celery_volumes_found = False
                    in_backend_volumes = False

                if in_celery_volumes and '  volumes:' in line and not celery_volumes_found:
                    # Add image paths after the volumes: line
                    for idx, path in enumerate(image_paths):
                        mount_point = f"/data{idx if idx > 0 else ''}"
                        final_lines.append(f"      - {path}:{mount_point}  # Forensic images (read-write for output)\n")
                    celery_volumes_found = True

            # Write back to file
            with open(self.docker_compose_path, 'w') as f:
                f.writelines(final_lines)

            print()
            self.print_success("Updated docker-compose.yml")
            print()

            if image_paths:
                print(f"{Colors.BOLD}Configured paths:{Colors.END}\n")
                for idx, path in enumerate(image_paths):
                    mount_point = f"/data{idx if idx > 0 else ''}"
                    print(f"  • {path}")
                    print(f"    → {mount_point} (in container)")
                print()

                self.print_info("Restart Dernvale for changes to take effect:")
                print(f"  docker-compose down")
                print(f"  ./scripts/start-testing-mode.sh")
            else:
                self.print_warning("No forensic image paths configured")
                self.print_info("Add paths using this script before running tests")

            return True

        except Exception as e:
            self.print_error(f"Failed to update docker-compose.yml: {e}")
            return False


def main():
    """Main function"""

    # Disable colors on Windows if needed
    if os.name == 'nt':
        Colors.disable()

    manager = PathManager()

    while True:
        manager.print_header("Dernvale Image Path Manager")

        print(f"{Colors.BOLD}Options:{Colors.END}\n")
        print(f"  {Colors.BOLD}1. Show current paths{Colors.END}")
        print(f"     View currently configured forensic image paths\n")

        print(f"  {Colors.BOLD}2. Add paths{Colors.END}")
        print(f"     Add new paths to existing configuration\n")

        print(f"  {Colors.BOLD}3. Remove paths{Colors.END}")
        print(f"     Remove specific paths from configuration\n")

        print(f"  {Colors.BOLD}4. Replace all paths{Colors.END}")
        print(f"     Remove all current paths and configure new ones\n")

        print(f"  {Colors.BOLD}5. Exit{Colors.END}\n")

        choice = input(f"{Colors.YELLOW}Select option (1-5): {Colors.END}").strip()

        if choice == '1':
            manager.show_current_paths()
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")

        elif choice == '2':
            manager.add_paths()
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")

        elif choice == '3':
            manager.remove_paths()
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")

        elif choice == '4':
            manager.replace_all_paths()
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")

        elif choice == '5':
            manager.print_info("Exiting")
            sys.exit(0)

        else:
            manager.print_error("Invalid option. Please enter 1-5.")
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")


if __name__ == '__main__':
    main()
