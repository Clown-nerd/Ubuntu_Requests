
import requests
import os
import hashlib
import mimetypes
from urllib.parse import urlparse
from datetime import datetime


class UbuntuImageFetcher:
    """Image fetcher implementing Ubuntu principles"""
    
    # Safe image content types
    ALLOWED_CONTENT_TYPES = [
        'image/jpeg', 'image/jpg', 'image/png', 
        'image/gif', 'image/webp', 'image/bmp'
    ]
    
    # Maximum file size (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    
    def __init__(self, directory="Fetched_Images"):
        """Initialize the fetcher with a target directory"""
        self.directory = directory
        self.downloaded_hashes = set()
        self.metadata_file = os.path.join(directory, ".metadata.txt")
        self._load_metadata()
    
    def _load_metadata(self):
        """Load metadata of previously downloaded images"""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    for line in f:
                        hash_value = line.strip()
                        if hash_value:
                            self.downloaded_hashes.add(hash_value)
            except Exception as e:
                print(f"⚠️  Could not load metadata: {e}")
    
    def _save_metadata(self, hash_value):
        """Save metadata for duplicate detection"""
        try:
            with open(self.metadata_file, 'a') as f:
                f.write(f"{hash_value}\n")
        except Exception as e:
            print(f"⚠️  Could not save metadata: {e}")
    
    def _calculate_hash(self, content):
        """Calculate SHA-256 hash of content for duplicate detection"""
        return hashlib.sha256(content).hexdigest()
    
    def _is_duplicate(self, content):
        """Check if image has been downloaded before"""
        hash_value = self._calculate_hash(content)
        return hash_value in self.downloaded_hashes, hash_value
    
    def _validate_url(self, url):
        """Validate URL format"""
        parsed = urlparse(url)
        if not parsed.scheme in ['http', 'https']:
            raise ValueError("URL must use HTTP or HTTPS protocol")
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        return True
    
    def _check_headers(self, response):
        """
        Challenge 4: Check important HTTP headers
        Returns: (is_valid, message)
        """
        headers = response.headers
        
        # Check Content-Type
        content_type = headers.get('Content-Type', '').lower().split(';')[0]
        if content_type not in self.ALLOWED_CONTENT_TYPES:
            return False, f"Unsupported content type: {content_type}"
        
        # Check Content-Length
        content_length = headers.get('Content-Length')
        if content_length:
            size = int(content_length)
            if size > self.MAX_FILE_SIZE:
                return False, f"File too large: {size / (1024*1024):.2f}MB (max: 10MB)"
        
        # Check for malicious indicators
        if 'Content-Disposition' in headers:
            disposition = headers['Content-Disposition']
            if 'attachment' not in disposition.lower():
                print("ℹ️  Note: Content-Disposition header present")
        
        return True, "Headers valid"
    
    def _get_safe_filename(self, url, content_type):
        """Extract or generate a safe filename"""
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        
        # If no filename in URL, generate one
        if not filename or '.' not in filename:
            extension = mimetypes.guess_extension(content_type) or '.jpg'
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"image_{timestamp}{extension}"
        
        # Sanitize filename (remove dangerous characters)
        safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        filename = ''.join(c if c in safe_chars else '_' for c in filename)
        
        return filename
    
    def fetch_image(self, url):
        """
        Fetch a single image from URL
        Returns: (success, message)
        """
        try:
            # Validate URL
            self._validate_url(url)
            print(f"🔗 Connecting to: {url}")
            
            # Challenge 2: Security precautions
            # Use timeout, verify SSL, set User-Agent
            headers = {
                'User-Agent': 'UbuntuImageFetcher/1.0 (Educational Purpose)'
            }
            
            # Make request with security measures
            response = requests.get(
                url, 
                timeout=10,
                verify=True,  # Verify SSL certificates
                headers=headers,
                stream=True  # Stream for large files
            )
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Challenge 4: Check HTTP headers
            is_valid, message = self._check_headers(response)
            if not is_valid:
                return False, f"❌ Security check failed: {message}"
            
            # Get the content
            content = response.content
            
            # Challenge 3: Check for duplicates
            is_duplicate, hash_value = self._is_duplicate(content)
            if is_duplicate:
                return False, "⚠️  Image already downloaded (duplicate detected)"
            
            # Create directory if it doesn't exist
            os.makedirs(self.directory, exist_ok=True)
            
            # Get safe filename
            content_type = response.headers.get('Content-Type', '').split(';')[0]
            filename = self._get_safe_filename(url, content_type)
            
            # Check if file already exists
            filepath = os.path.join(self.directory, filename)
            counter = 1
            base, ext = os.path.splitext(filename)
            while os.path.exists(filepath):
                filename = f"{base}_{counter}{ext}"
                filepath = os.path.join(self.directory, filename)
                counter += 1
            
            # Save the image in binary mode
            with open(filepath, 'wb') as f:
                f.write(content)
            
            # Save metadata for duplicate detection
            self.downloaded_hashes.add(hash_value)
            self._save_metadata(hash_value)
            
            # Calculate file size
            size_kb = len(content) / 1024
            
            print(f"✓ Successfully fetched: {filename}")
            print(f"✓ Image saved to {filepath}")
            print(f"✓ File size: {size_kb:.2f} KB")
            
            return True, filename
            
        except requests.exceptions.Timeout:
            return False, "❌ Connection timeout - the server took too long to respond"
        
        except requests.exceptions.SSLError:
            return False, "❌ SSL Certificate verification failed - connection not secure"
        
        except requests.exceptions.ConnectionError:
            return False, "❌ Connection error - could not reach the server"
        
        except requests.exceptions.HTTPError as e:
            return False, f"❌ HTTP Error {e.response.status_code}: {e.response.reason}"
        
        except ValueError as e:
            return False, f"❌ Validation error: {e}"
        
        except Exception as e:
            return False, f"❌ Unexpected error: {e}"
    
    def fetch_multiple_images(self, urls):
        """
        Challenge 1: Handle multiple URLs at once
        """
        print(f"\n{'='*60}")
        print(f"📦 Fetching {len(urls)} images...")
        print(f"{'='*60}\n")
        
        results = {'success': 0, 'failed': 0, 'duplicate': 0}
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{len(urls)}] Processing...")
            success, message = self.fetch_image(url)
            
            if success:
                results['success'] += 1
            elif 'duplicate' in message.lower():
                results['duplicate'] += 1
            else:
                results['failed'] += 1
                print(message)
            
            print("-" * 60)
        
        return results


def display_banner():
    """Display Ubuntu-inspired welcome banner"""
    banner = """
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║           🌍 UBUNTU IMAGE FETCHER 🌍                      ║
║                                                            ║
║              "I am because we are"                         ║
║                                                            ║
║   A tool for mindfully collecting images from the web      ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
"""
    print(banner)


def get_user_choice():
    """Get user's choice for single or multiple downloads"""
    print("\nOptions:")
    print("1. Download a single image")
    print("2. Download multiple images")
    print("3. Exit")
    
    while True:
        choice = input("\nSelect an option (1-3): ").strip()
        if choice in ['1', '2', '3']:
            return choice
        print("❌ Invalid choice. Please enter 1, 2, or 3.")


def main():
    """Main program function"""
    display_banner()
    
    # Initialize the fetcher
    fetcher = UbuntuImageFetcher()
    
    while True:
        choice = get_user_choice()
        
        if choice == '3':
            print("\n" + "="*60)
            print("🙏 Thank you for using Ubuntu Image Fetcher")
            print("Connection strengthened. Community enriched.")
            print("="*60)
            break
        
        elif choice == '1':
            # Single image download
            print("\n" + "-"*60)
            url = input("Please enter the image URL: ").strip()
            
            if not url:
                print("❌ URL cannot be empty")
                continue
            
            print("-"*60)
            success, message = fetcher.fetch_image(url)
            
            if not success:
                print(message)
            else:
                print("\n✨ Connection strengthened. Community enriched.")
        
        elif choice == '2':
            # Multiple image download
            print("\n" + "-"*60)
            print("Enter image URLs (one per line)")
            print("Enter a blank line when done:")
            print("-"*60)
            
            urls = []
            while True:
                url = input(f"URL {len(urls) + 1}: ").strip()
                if not url:
                    break
                urls.append(url)
            
            if not urls:
                print("❌ No URLs provided")
                continue
            
            results = fetcher.fetch_multiple_images(urls)
            
            # Display summary
            print("\n" + "="*60)
            print("📊 DOWNLOAD SUMMARY")
            print("="*60)
            print(f"✅ Successful: {results['success']}")
            print(f"⚠️  Duplicates: {results['duplicate']}")
            print(f"❌ Failed: {results['failed']}")
            print(f"📁 Total in library: {len(fetcher.downloaded_hashes)}")
            print("="*60)
            print("\n✨ Connection strengthened. Community enriched.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Program interrupted by user")
        print("Connection strengthened. Community enriched.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("Please report this issue to maintain community trust.")
