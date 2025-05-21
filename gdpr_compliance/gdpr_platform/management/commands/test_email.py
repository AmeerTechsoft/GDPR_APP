from django.core.management.base import BaseCommand
from django.core.mail import EmailMessage
from django.conf import settings
import sys
import os
import socket
import ssl

class Command(BaseCommand):
    help = 'Test email configuration by sending a test email'

    def add_arguments(self, parser):
        parser.add_argument('recipient_email', type=str, help='The email address to send the test email to')

    def handle(self, *args, **options):
        recipient_email = options['recipient_email']
        
        # Debug information
        self.stdout.write("\nEnvironment Variables:")
        self.stdout.write(f"EMAIL_HOST_USER in env: {os.environ.get('EMAIL_HOST_USER', 'Not found')}")
        self.stdout.write(f"EMAIL_HOST_PASSWORD in env: {'Set' if os.environ.get('EMAIL_HOST_PASSWORD') else 'Not found'}")
        
        self.stdout.write("\nDjango Settings:")
        self.stdout.write(f"EMAIL_BACKEND: {settings.EMAIL_BACKEND}")
        self.stdout.write(f"EMAIL_HOST: {settings.EMAIL_HOST}")
        self.stdout.write(f"EMAIL_PORT: {settings.EMAIL_PORT}")
        self.stdout.write(f"EMAIL_USE_TLS: {settings.EMAIL_USE_TLS}")
        self.stdout.write(f"EMAIL_USE_SSL: {settings.EMAIL_USE_SSL}")
        self.stdout.write(f"EMAIL_HOST_USER: {settings.EMAIL_HOST_USER}")
        self.stdout.write(f"EMAIL_HOST_PASSWORD: {'Set' if settings.EMAIL_HOST_PASSWORD else 'Not set'}")
        self.stdout.write(f"DEFAULT_FROM_EMAIL: {settings.DEFAULT_FROM_EMAIL}")
        
        try:
            self.stdout.write("\nChecking connection to SMTP server...")
            # Create SSL context
            context = ssl.create_default_context()
            
            # Test socket connection with SSL if needed
            sock = socket.create_connection((settings.EMAIL_HOST, settings.EMAIL_PORT), timeout=10)
            if settings.EMAIL_USE_SSL:
                sock = context.wrap_socket(sock, server_hostname=settings.EMAIL_HOST)
            sock.close()
            self.stdout.write(self.style.SUCCESS("Successfully connected to SMTP server"))
            
            self.stdout.write("\nAttempting to send email...")
            email = EmailMessage(
                subject='Test Email from GDPR Compliance Platform',
                body='This is a test email from your Django application. If you receive this, your email configuration is working correctly.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[recipient_email],
                reply_to=[settings.DEFAULT_FROM_EMAIL],
                headers={
                    'X-Priority': '1',
                    'X-MSMail-Priority': 'High',
                    'Importance': 'High',
                }
            )
            email.send(fail_silently=False)
            self.stdout.write(self.style.SUCCESS('\nTest email sent successfully!'))
            
        except socket.error as e:
            self.stdout.write(self.style.ERROR(f'\nConnection error: {str(e)}'))
            self.stdout.write(self.style.WARNING('\nTroubleshooting tips:'))
            self.stdout.write('1. Check if the port is blocked by your firewall')
            self.stdout.write(f'2. Try allowing outbound connections to smtp.gmail.com:{settings.EMAIL_PORT}')
            self.stdout.write('3. Try using a different network (e.g., mobile hotspot)')
            self.stdout.write('4. Check if your antivirus is blocking the connection')
            sys.exit(1)
            
        except ssl.SSLError as e:
            self.stdout.write(self.style.ERROR(f'\nSSL error: {str(e)}'))
            self.stdout.write(self.style.WARNING('\nTroubleshooting tips:'))
            self.stdout.write('1. Check if your system\'s SSL certificates are up to date')
            self.stdout.write('2. Try updating your Python version')
            self.stdout.write('3. Check if any security software is intercepting SSL connections')
            sys.exit(1)
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'\nError sending email: {str(e)}'))
            self.stdout.write(self.style.WARNING('\nTroubleshooting tips:'))
            self.stdout.write('1. Check if your Gmail account has 2FA enabled')
            self.stdout.write('2. Verify that you\'re using an App Password if 2FA is enabled')
            self.stdout.write('3. Try generating a new App Password')
            self.stdout.write('4. Check if your Gmail account has any security blocks')
            self.stdout.write('5. Try signing in to Gmail web interface to check for any security alerts')
            sys.exit(1) 