Inoseek Parking Management App Definition
App Overview
Inoseek is a driver-focused mobile app for seamless parking management, integrating with an external system (e.g., cameras/sensors) for automatic car detection, payment deduction, and exit processing. It allows users to register, manage vehicles, track parking duration, view transactions, and access support, with a modern UI/UX.

Name: Inoseek
Tagline: Park and Dash
Brand Color: Primary Blue (#1E90FF), Secondary Light Blue (#87CEEB), Accent Dark Blue (#4169E1)
Logo: "Inoseek" in Montserrat Bold, #1E90FF, with a minimalist parking icon (e.g., car or "P") in the "O".
Target Audience: Urban drivers in Kenya (phone format: 2547XXXXXXXX or 2541XXXXXXXX).
Platform: React Native for iOS/Android, optimized for animations and real-time updates.

Branding Guidelines

Typography: Montserrat Bold (headings, 24px), Roboto Regular (body, 16px), Roboto Light (captions, 14px).
Color Palette:
Primary Blue (#1E90FF): Buttons, logo, active states.
Secondary Light Blue (#87CEEB): Gradients, backgrounds.
Accent Dark Blue (#4169E1): Hover, secondary actions.
Neutral: White (#FFFFFF), Gray (#333333), Light Gray (#E0E0E0).
Error: Red (#FF4444), Success: Green (#00C851).


Logo Usage: Centered on Welcome Screen (48px), top-left in headers (24px), 16px padding.
Iconography: Material Icons, 24px, tinted #1E90FF or #4169E1.
Animations: 300ms ease-in-out for buttons, 500ms for screen transitions, Lottie for spinners.
Tone: Friendly, efficient, transparent, emphasizing automated parking ("Park and Dash").
Dark Mode: Background #121212, text #E0E0E0, blue shades darken (e.g., #1E90FF → #1565C0).
Notifications: Push/in-app alerts for payment deductions and exit events, styled with #1E90FF.

Duration Tracking Feature

Overview: Tracks parking duration in real-time from entry (CheckNumberPlate) to exit (ExitVehicle), triggered by the external system.
Functionality:
Starts timer when external system detects car and creates transaction via CheckNumberPlate.
Updates every second (HH:MM:SS) on Home Screen (active transaction card).
Stops when external system triggers ExitVehicle, saving final duration.
Persists across sessions using AsyncStorage.


UI Integration:
Live timer in Home Screen's active transaction card (flip animation).
Final duration in Exit Vehicle Screen and Transactions Screen.


Technical Notes:
Use setInterval with entry_time from TransactionsAPIView.
Cache entry_time and transaction ID locally.
Handle app background/foreground for timer accuracy.



External System Integration

Car Detection: External system (e.g., cameras) detects car number plate and parking space, triggering CheckNumberPlate to start a transaction.
Payment Deduction: External system initiates payment via InitiatePaymentAPIView when car is detected, deducting from user balance. App receives updates via PaymentStatusCallbackAPIView.
Exit Processing: External system detects car exit, triggers ExitVehicle with transaction_id, exit_time, and fee. App displays updated transaction.
Notifications: Push notifications (via Firebase or similar) alert users of deductions and exits, with in-app banners for real-time updates.

Screens and Functionalities
Screens are designed with glassmorphism (frosted cards), neumorphism (soft shadows), animations, and haptics for an awesome UI/UX. QR code scanning is removed as per requirements.
1. Welcome Screen

Purpose: Introduce Inoseek and guide to authentication.
Functionality:
Display logo and tagline.
Navigate to Login or Register.


API Endpoints: None.
UI Elements:
Logo: "Inoseek" (Montserrat Bold, 36px, #1E90FF, parking icon in "O").
Tagline: "Park and Dash" (Roboto, 18px, #333333).
Buttons:
"Login" (#1E90FF, white text, 16px padding, 300ms scale, haptic).
"Register" (#1E90FF outline, 300ms fade-in).


Background: White, #87CEEB gradient top 20%, glassmorphic overlay.
Animation: Logo fades in (500ms), buttons slide up.


UX Notes: Centered layout, high contrast, accessible button sizes.

2. Register Screen

Purpose: User registration.
Functionality:
Collect name, email, phone (2547XXXXXXXX or 2541XXXXXXXX), password (min 8 chars).
Client-side validation (email/phone regex, password length).
Submit to RegisterAPIView.
Success: Show "Check email for OTP", navigate to OTP Verification.
Error: Display error (e.g., email exists).


API Endpoints: POST /register/
UI Elements:
Header: Logo (24px, #1E90FF).
Inputs: Name, Email, Phone, Password (Roboto, 16px, #E0E0E0 border, #1E90FF focus, neumorphic).
Submit Button: "Register" (#1E90FF, 300ms scale, haptic).
Error: Red (#FF4444), 200ms fade-in.
Link: "Already have an account? Log in" (#4169E1, 300ms underline).
Background: White, #87CEEB gradient header.
Animation: Inputs slide in sequentially (100ms delay).


UX Notes: Auto-focus first input, keyboard-aware scrolling, live validation.

3. OTP Verification Screen

Purpose: Verify email with OTP.
Functionality:
Collect 6-digit OTP, hidden user_id.
Submit to VerifyOTPAPIView.
Success: Auto-login, navigate to Home.
Error: Show invalid/expired OTP.
Resend via ResendOTPAPIView (30s cooldown).


API Endpoints:
POST /verify-otp/
POST /resend-otp/


UI Elements:
Header: Logo.
OTP Inputs: 6 boxes (16px, #1E90FF focus, auto-advance).
Submit Button: "Verify" (#1E90FF, haptic).
Resend Button: "Resend OTP" (#4169E1 enabled, gray disabled, 300ms fade).
Timer: "Resend in 00:30" (Roboto, 14px, #333333, animated).
Error: Red text.
Background: White, glassmorphic OTP card.
Animation: Boxes pulse on focus, timer digits flip.


UX Notes: Auto-submit on 6th digit, haptic on resend.

4. Login Screen

Purpose: Authenticate users.
Functionality:
Collect email, password.
Submit to LoginAPIView.
Success: Store tokens, navigate to Home.
Error: Show invalid credentials/unverified email.


API Endpoints: POST /login/
UI Elements:
Header: Logo.
Inputs: Email, Password (#E0E0E0 border, #1E90FF focus).
Submit Button: "Login" (#1E90FF, haptic).
Error: Red text.
Links:
"Don't have an account? Sign up" (#4169E1).
"Forgot Password?" (#4169E1, placeholder).


Background: White, #87CEEB gradient header.
Animation: Inputs fade in, button scales.


UX Notes: Password show/hide toggle, auto-fill support.

5. Home Screen

Purpose: Hub for parking info and actions.
Functionality:
Show name, balance (UserProfileAPIView).
Display active transaction with live duration timer (TransactionsAPIView).
Show notifications for automatic payment deductions and exits.
Actions: Top-up, Manage Cars, view Transactions/Support.


API Endpoints:
GET /profile/
GET /transactions/


UI Elements:
Header: Logo, name (Montserrat Bold, 20px), balance (#1E90FF, 18px).
Notification Banner: Payment/exit alerts (#1E90FF background, 500ms slide-in, haptic).
Active Transaction Card: Plate, space, entry time, live duration (HH:MM:SS, flip animation, glassmorphic, #E0E0E0 border).
Action Buttons:
"Top-up Balance" (#1E90FF)
"Manage Cars" (#1E90FF)


Bottom Navigation: Icons (Home, Transactions, Profile, Support, #1E90FF active, 300ms fade).
Background: White, #87CEEB gradient header.
Animation: Card slides in, timer animates, banner fades.
Haptics: Vibration on notifications, button presses.


UX Notes: Swipe to refresh, tap card for details, dismissable notifications.

6. Profile Screen

Purpose: View/edit profile.
Functionality:
Display name, email, phone, balance, verification (UserProfileAPIView).
Edit fields (UserProfileUpdateAPIView).
Change password (SetPasswordAPIView).
Logout (clear tokens).


API Endpoints:
GET /profile/
PATCH /profile/update/
POST /set-password/


UI Elements:
Header: Logo.
Profile Card: Details (Roboto, 16px, glassmorphic).
Edit Inputs: Name, Email, Phone (#1E90FF focus).
Buttons:
"Edit Profile" (#1E90FF)
"Change Password" (#4169E1)
"Save Changes" (#1E90FF)
"Logout" (#FF4444 outline, haptic).


Messages: Red/Green text.
Background: White.
Animation: Card fades in, inputs slide on edit.


UX Notes: Confirm logout with modal, live validation.

7. Cars Screen

Purpose: Manage vehicles.
Functionality:
List cars (CarListCreateAPIView).
Add car (CarListCreateAPIView).
Toggle active (CarToggleAPIView).
Delete car (CarDeleteAPIView).
Validate number plate (8 alphanumeric).


API Endpoints:
GET /cars/
POST /cars/
PATCH /cars/{car_id}/toggle/
DELETE /cars/{car_id}/delete/


UI Elements:
Header: Logo.
Car List: Cards (plate, model, active status, glassmorphic).
Toggle Switch: #1E90FF active, 300ms slide.
Delete Icon: #FF4444, haptic.
Add Button: #1E90FF, modal with inputs.
Messages: Red/Green text.
Background: White.
Animation: Cards slide in, modal zooms.


UX Notes: Confirm delete, auto-uppercase plate.

8. Check Number Plate Screen

Purpose: Confirm parking session start (initiated externally).
Functionality:
Display number plate and parking space ID from external system (CheckNumberPlate).
Success: Show transaction with duration timer start.
Alert: Show unregistered car alert, link to add car.
Error: Display message (e.g., low balance).


API Endpoints: POST /check-number-plate/
UI Elements:
Header: Logo.
Notification Banner: "Car detected" with plate, space ID (#1E90FF, 500ms slide-in, haptic).
Transaction Card: Plate, space, entry time, live duration (HH:MM:SS, flip animation, glassmorphic).
Alert Card: Details, "Add Car" (#4169E1).
Messages: Red/Green text.
Background: White.
Animation: Card fades in, banner slides.


UX Notes: Read-only display, auto-refresh on detection, dismissable banner.

9. Exit Vehicle Screen

Purpose: Display completed transaction after external exit detection.
Functionality:
Show transaction details with final duration, fee, payment status (TransactionsAPIView, updated via ExitVehicle by external system).
Display notification for exit and payment deduction.


API Endpoints:
GET /transactions/
POST /exit-vehicle/ (called externally)


UI Elements:
Header: Logo.
Notification Banner: "Exit detected" with payment status (#1E90FF, 500ms slide-in, haptic).
Transaction Card: Plate, space, entry/exit time, final duration, fee (glassmorphic).
Messages: Red/Green text.
Background: White.
Animation: Card fades in, banner slides.


UX Notes: Auto-refresh on exit, dismissable banner, tap for transaction history.

10. Payment Screen

Purpose: Manual balance top-up (parking payments handled externally).
Functionality:
Collect amount, phone (pre-filled, locked), no transaction ID for top-ups.
Validate phone, amount.
Submit to InitiatePaymentAPIView.
Success: Show payment status, update balance.
Error: Display message.


API Endpoints: POST /initiate-payment/
UI Elements:
Header: Logo.
Inputs: Amount, Phone (locked, #1E90FF focus).
Submit Button: "Top-up Now" (#1E90FF, haptic).
Messages: Red/Green text.
Background: White, glassmorphic inputs.
Animation: Inputs slide in, button scales.


UX Notes: Numeric keyboard for amount, confirm payment with modal.

11. Transactions Screen

Purpose: View transaction history.
Functionality:
List transactions with duration, fee, status (TransactionsAPIView).
Show payment status updates from external deductions.


API Endpoints: GET /transactions/
UI Elements:
Header: Logo.
Transaction List: Cards (plate, space, duration, fee, status, glassmorphic).
Details Modal: Full transaction info.
Background: White.
Animation: Cards slide in, modal zooms.


UX Notes: Filter by status, swipe to refresh.

12. Support Screen

Purpose: Manage support tickets.
Functionality:
List tickets, create new (SupportTicketListCreateAPIView).
Show ticket details.


API Endpoints:
GET /support-tickets/
POST /support-tickets/


UI Elements:
Header: Logo.
Ticket List: Cards (subject, status, date, glassmorphic).
Create Button: #1E90FF, modal with inputs.
Messages: Red/Green text.
Background: White.
Animation: Cards fade in, modal zooms.


UX Notes: Auto-focus subject in modal, validate inputs.

Navigation Flow

Unauthenticated: Welcome → Login/Register → OTP Verification → Home
Authenticated: Home ↔ Profile, Cars, Transactions, Support
Home → Check Number Plate (view only) → Success/Alert
Home → Exit Vehicle (view only) → Summary
Home → Payment → Top-up Confirmation
Cars → Add/Edit/Delete
Support → Create Ticket



Technical Considerations

Framework: React Native, Reanimated for animations, Haptics for feedback.
API: Axios with JWT, handle external ExitVehicle calls.
Storage: AsyncStorage for tokens, transaction cache.
Timer: setInterval with entry_time, sync with external system.
Notifications: Firebase Push for payment/exit alerts, in-app banners.
Accessibility: ARIA labels, WCAG 2.1 contrast ratios.
Localization: English/Swahili, Kenyan phone formats.
Real-time: WebSocket for PaymentStatusCallbackAPIView, poll TransactionsAPIView.

Future Enhancements

Forgot Password.
Offline transaction viewing.
Real-time parking space availability.


Refer from this defined Endpoints

from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from django.conf import settings
from django.db import transaction
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
import requests
import logging
import random
import string
import re
from decimal import Decimal
from users.models import User
from cars.models import Car
from alerts.models import Alert
from parking_lots.models import ParkingLot, ParkingSpace
from parking_transactions.models import ParkingTransaction
from .serializers import UserSerializer, CarSerializer, ParkingTransactionSerializer, AlertSerializer, SupportTicketSerializer

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize Brevo API client
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = settings.BREVO_API_KEY
brevo_api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

User = get_user_model()

class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        name = request.data.get('name')
        email = request.data.get('email')
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')

        logger.info(f"Registering user - email: {email}, phone: {phone_number}")

        # Validate inputs
        if not all([name, email, phone_number, password]):
            return Response(
                {'status': 'error', 'message': 'All fields are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            return Response(
                {'status': 'error', 'message': 'Invalid email format'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not re.match(r'^254[17]\d{8}$', phone_number):
            return Response(
                {'status': 'error', 'message': 'Invalid phone number format. Use 2547XXXXXXXX or 2541XXXXXXXX'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if len(password) < 8:
            return Response(
                {'status': 'error', 'message': 'Password must be at least 8 characters long'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(email=email).exists():
            return Response(
                {'status': 'error', 'message': 'Email already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if User.objects.filter(phone_number=phone_number).exists():
            return Response(
                {'status': 'error', 'message': 'Phone number already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.create_user(
                email=email,
                name=name,
                phone_number=phone_number,
                password=password,
                role='driver'  # Default role for driver app
            )
            otp = ''.join(random.choices(string.digits, k=6))
            user.set_otp(otp)
            user.save()

            logger.info(f"Generated OTP for {email}: [REDACTED]")

            try:
                send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                    to=[{"email": email, "name": name}],
                    sender={"email": settings.BREVO_SENDER_EMAIL, "name": "inoseek Team"},
                    template_id=settings.BREVO_OTP_TEMPLATE_ID,
                    params={"FIRSTNAME": name, "OTP_CODE": otp}
                )
                brevo_api_instance.send_transac_email(send_smtp_email)
                logger.info(f"OTP email sent to {email}")
            except ApiException as e:
                logger.error(f"Error sending OTP email: {str(e)}, Status: {e.status}, Body: {e.body}")
                user.delete()
                return Response(
                    {'status': 'error', 'message': 'Failed to send OTP email'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response({
                'status': 'success',
                'message': 'User registered successfully. Check your email for OTP.',
                'user_id': str(user.id),
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error during registration: {str(e)}")
            return Response(
                {'status': 'error', 'message': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class VerifyOTPAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get('user_id')
        otp = request.data.get('otp')

        logger.info(f"Verifying OTP - user_id: {user_id}")

        if not all([user_id, otp]):
            return Response(
                {'status': 'error', 'message': 'User ID and OTP are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(id=user_id)
            if not user.otp:
                logger.warning(f"No OTP found for user {user.email}")
                return Response(
                    {'status': 'error', 'message': 'No OTP found for this user'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not check_password(str(otp), user.otp):
                logger.warning(f"Invalid OTP attempt for user {user.email}")
                return Response(
                    {'status': 'error', 'message': 'Invalid OTP'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if user.otp_created_at and user.otp_created_at < (timezone.now() - timezone.timedelta(minutes=5)):
                logger.warning(f"OTP expired for user {user.email}")
                return Response(
                    {'status': 'error', 'message': 'OTP expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user.is_active = True
            user.is_email_verified = True
            user.otp = None
            user.otp_created_at = None
            user.save()
            logger.info(f"User {user.email} verified successfully")

            try:
                send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                    to=[{"email": user.email, "name": user.name}],
                    sender={"email": settings.BREVO_SENDER_EMAIL, "name": "inoseek Team"},
                    template_id=settings.BREVO_WELCOME_TEMPLATE_ID,
                    params={"FIRSTNAME": user.name}
                )
                brevo_api_instance.send_transac_email(send_smtp_email)
                logger.info(f"Welcome email sent to {user.email}")
            except ApiException as e:
                logger.error(f"Error sending welcome email: {str(e)}, Status: {e.status}, Body: {e.body}")

            return Response({
                'status': 'success',
                'message': 'OTP verified',
                'user_id': str(user.id),
                'name': user.name,
                'email': user.email,
                'phone_number': user.phone_number,
                'balance': str(user.balance),
                'is_email_verified': user.is_email_verified,
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            logger.error(f"User not found for user_id: {user_id}")
            return Response(
                {'status': 'error', 'message': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error verifying OTP: {str(e)}")
            return Response(
                {'status': 'error', 'message': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class ResendOTPAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response(
                {'status': 'error', 'message': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
            if user.is_active:
                logger.info(f"Resend OTP attempt for already verified user: {email}")
                return Response(
                    {'status': 'error', 'message': 'User already verified. Please log in.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if user.otp_created_at and (timezone.now() - user.otp_created_at).total_seconds() < 30:
                return Response(
                    {'status': 'error', 'message': 'Please wait 30 seconds before requesting a new OTP'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )

            otp = ''.join(random.choices(string.digits, k=6))
            user.set_otp(otp)
            user.save()
            logger.info(f"Resent OTP for {email}: [REDACTED]")

            try:
                send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                    to=[{"email": email, "name": user.name}],
                    sender={"email": settings.BREVO_SENDER_EMAIL, "name": "inoseek Team"},
                    template_id=settings.BREVO_OTP_RESEND_TEMPLATE_ID,
                    params={"FIRSTNAME": user.name, "OTP_CODE": otp}
                )
                brevo_api_instance.send_transac_email(send_smtp_email)
                logger.info(f"OTP resend email sent to {email}")
            except ApiException as e:
                logger.error(f"Error sending OTP resend email: {str(e)}, Status: {e.status}, Body: {e.body}")
                return Response(
                    {'status': 'error', 'message': 'Failed to resend OTP email. Please try again later.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {'status': 'success', 'message': 'OTP resent successfully'},
                status=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            logger.error(f"User not found for email: {email}")
            return Response(
                {'status': 'error', 'message': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error resending OTP: {str(e)}")
            return Response(
                {'status': 'error', 'message': 'An unexpected error occurred'},
                status=status.HTTP_400_BAD_REQUEST
            )

class SetPasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        password = request.data.get('password')
        if not password or len(password) < 8:
            logger.error(f"Invalid password attempt for user {request.user.email}")
            return Response(
                {'status': 'error', 'message': 'Password must be at least 8 characters long'},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            user = request.user
            user.set_password(password)
            user.save()
            logger.info(f"Password set successfully for user {user.email}")
            return Response({'status': 'success', 'message': 'Password set successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error setting password for user {request.user.email}: {str(e)}")
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not all([email, password]):
            return Response(
                {'status': 'error', 'message': 'Email and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.error(f"Login attempt with non-existent email: {email}")
            return Response(
                {'status': 'error', 'message': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        if not user.check_password(password):
            logger.warning(f"Invalid password attempt for user {email}")
            return Response(
                {'status': 'error', 'message': 'Invalid password'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_email_verified:
            logger.warning(f"Unverified email login attempt for user {email}")
            return Response(
                {'status': 'error', 'message': 'Email not verified'},
                status=status.HTTP_403_FORBIDDEN
            )

        refresh = RefreshToken.for_user(user)
        logger.info(f"User {email} logged in successfully")
        return Response({
            'status': 'success',
            'message': 'Login successful',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user': UserSerializer(user).data
        }, status=status.HTTP_200_OK)

class UserProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logger.info(f"Profile retrieved for user {request.user.email}")
        return Response(UserSerializer(request.user).data, status=status.HTTP_200_OK)

class UserProfileUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        user = request.user
        data = request.data
        if 'email' in data and data['email'] != user.email:
            if User.objects.filter(email=data['email']).exists():
                logger.error(f"Email update failed for user {user.email}: Email {data['email']} already exists")
                return Response(
                    {'status': 'error', 'message': 'Email already exists'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        if 'phone_number' in data and data['phone_number'] != user.phone_number:
            if not re.match(r'^254[17]\d{8}$', data['phone_number']):
                logger.error(f"Invalid phone number format for user {user.email}")
                return Response(
                    {'status': 'error', 'message': 'Invalid phone number format. Use 2547XXXXXXXX or 2541XXXXXXXX'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if User.objects.filter(phone_number=data['phone_number']).exists():
                logger.error(f"Phone number update failed for user {user.email}: Phone {data['phone_number']} already exists")
                return Response(
                    {'status': 'error', 'message': 'Phone number already exists'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        serializer = UserSerializer(user, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Profile updated successfully for user {user.email}")
            return Response({
                'status': 'success',
                'message': 'Profile updated successfully',
                'user_id': str(user.id),
                'name': user.name,
                'email': user.email,
                'phone_number': user.phone_number,
                'balance': str(user.balance),
                'is_email_verified': user.is_email_verified
            }, status=status.HTTP_200_OK)
        logger.error(f"Profile update failed for user {user.email}: {serializer.errors}")
        return Response({
            'status': 'error',
            'message': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class CarListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        cars = Car.objects.filter(user=request.user)
        logger.info(f"Cars retrieved for user {request.user.email}")
        return Response(CarSerializer(cars, many=True).data, status=status.HTTP_200_OK)

    def post(self, request):
        data = request.data
        data['user'] = request.user.id
        if 'number_plate' in data:
            data['number_plate'] = data['number_plate'].upper().replace(' ', '')
            if not re.match(r'^[A-Z0-9]{1,8}$', data['number_plate']):
                logger.error(f"Invalid number plate format for user {request.user.email}: {data['number_plate']}")
                return Response(
                    {'status': 'error', 'message': 'Invalid number plate format. Use up to 8 alphanumeric characters'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        serializer = CarSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Car created for user {request.user.email}: {data['number_plate']}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.error(f"Car creation failed for user {request.user.email}: {serializer.errors}")
        return Response({'status': 'error', 'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class CarToggleAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, car_id):
        try:
            car = Car.objects.get(id=car_id, user=request.user)
            car.is_active = not car.is_active
            car.save()
            logger.info(f"Car {car.number_plate} toggled to active={car.is_active} for user {request.user.email}")
            return Response(CarSerializer(car).data, status=status.HTTP_200_OK)
        except Car.DoesNotExist:
            logger.error(f"Car not found for user {request.user.email}, id: {car_id}")
            return Response(
                {'status': 'error', 'message': 'Car not found or not authorized'},
                status=status.HTTP_404_NOT_FOUND
            )

class CarDeleteAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, car_id):
        try:
            car = Car.objects.get(id=car_id, user=request.user)
            number_plate = car.number_plate
            car.delete()
            logger.info(f"Car {number_plate} deleted for user {request.user.email}")
            return Response(
                {'status': 'success', 'message': 'Car deleted successfully'},
                status=status.HTTP_204_NO_CONTENT
            )
        except Car.DoesNotExist:
            logger.error(f"Car not found for user {request.user.email}, id: {car_id}")
            return Response(
                {'status': 'error', 'message': 'Car not found or not authorized'},
                status=status.HTTP_404_NOT_FOUND
            )

class InitiatePaymentAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        amount = request.data.get("amount")
        parking_transaction_id = request.data.get("parking_transaction_id")
        phone_number = request.data.get("phone_number")

        logger.info(f"Initiating payment for user {user.email}, transaction_id: {parking_transaction_id}")

        # Validate inputs
        if not amount:
            logger.error(f"Amount missing for user {user.email}")
            return Response(
                {"status": "error", "message": "Amount is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not phone_number:
            logger.error(f"Phone number missing for user {user.email}")
            return Response(
                {"status": "error", "message": "Phone number is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not re.match(r'^254[17]\d{8}$', phone_number):
            logger.error(f"Invalid phone number format for user {user.email}: {phone_number}")
            return Response(
                {"status": "error", "message": "Invalid phone number format. Use 2547XXXXXXXX or 2541XXXXXXXX"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Normalize user's stored phone number
        stored_phone = user.phone_number
        if stored_phone.startswith('0'):
            normalized_stored_phone = '254' + stored_phone[1:]
        else:
            normalized_stored_phone = stored_phone

        # Validate phone number match
        if phone_number != normalized_stored_phone:
            logger.error(f"Phone number mismatch for user {user.email}: provided {phone_number}, expected {normalized_stored_phone}")
            return Response(
                {"status": "error", "message": "Phone number does not match user account"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            amount = Decimal(amount)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            amount_str = f"{amount:.2f}"
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid amount for user {user.email}: {amount}")
            return Response(
                {"status": "error", "message": "Amount must be a positive number"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Generate order ID
        order_id = (
            f"topup-{user.id}-{int(timezone.now().timestamp())}"
            if not parking_transaction_id
            else f"park-{parking_transaction_id}"
        )

        # Prepare payment payload
        payload = {
            "order_id": order_id,
            "user_id": str(user.id),
            "amount": amount_str,
            "client_till_number": settings.CLIENT_TILL_NUMBER,
            "phone_number": phone_number
        }

        logger.info(f"Payment payload for user {user.email}: {payload}")

        # Send request to payment service
        try:
            response = requests.post(
                f"{settings.PAYMENTS_API_URL}/api/v1/payments/process/",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            logger.info(f"Payment API response for user {user.email} [{response.status_code}]: {response.text}")

            if response.status_code >= 400:
                try:
                    error_json = response.json()
                except ValueError:
                    error_json = response.text
                logger.error(f"Payment API error for user {user.email}: {error_json}")
                return Response(
                    {
                        "status": "error",
                        "message": "Payment service returned an error",
                        "details": error_json,
                        "status_code": response.status_code
                    },
                    status=status.HTTP_502_BAD_GATEWAY
                )

            payment_data = response.json()

            # Update local transaction or balance
            with transaction.atomic():
                if not parking_transaction_id:
                    default_lot, _ = ParkingLot.objects.get_or_create(
                        name="Top-up Lot",
                        defaults={"location": "N/A", "total_spaces": 0, "client": None}
                    )
                    default_space, _ = ParkingSpace.objects.get_or_create(
                        parking_lot=default_lot,
                        space_number="TOPUP",
                        defaults={"is_occupied": False}
                    )
                    car = Car.objects.filter(user=user, is_active=True).first()
                    if not car:
                        logger.error(f"No active car found for user {user.email}")
                        return Response(
                            {"status": "error", "message": "No active car found for user"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    ParkingTransaction.objects.create(
                        car=car,
                        parking_space=default_space,
                        entry_time=timezone.now(),
                        fee=amount,
                        status='topup',
                        payment_status='PENDING',
                        created_at=timezone.now(),
                    )
                    user.balance = (user.balance or Decimal('0')) + amount
                    user.save()
                else:
                    try:
                        transaction = ParkingTransaction.objects.select_related('car__user').get(
                            id=parking_transaction_id, car__user=user, status='ongoing'
                        )
                    except ParkingTransaction.DoesNotExist:
                        logger.error(f"Invalid or unauthorized transaction {parking_transaction_id} for user {user.email}")
                        return Response(
                            {"status": "error", "message": "Invalid or unauthorized parking transaction"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    transaction.fee = amount
                    transaction.status = 'completed'
                    transaction.payment_status = 'PENDING'
                    transaction.exit_time = timezone.now()
                    transaction.duration = transaction.exit_time - transaction.entry_time
                    transaction.save()

            return Response({
                "status": "success",
                "message": "Payment initiated successfully",
                "data": payment_data
            }, status=status.HTTP_201_CREATED)

        except requests.exceptions.RequestException as e:
            logger.error(f"Payment request failed for user {user.email}: {str(e)}")
            return Response(
                {"status": "error", "message": "Failed to connect to payment service", "details": str(e)},
                status=status.HTTP_502_BAD_GATEWAY
            )
        except Exception as e:
            logger.error(f"Unexpected error during payment for user {user.email}: {str(e)}")
            return Response(
                {"status": "error", "message": "An unexpected error occurred", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PaymentStatusCallbackAPIView(APIView):
    permission_classes = [AllowAny]  # Payment service may not send auth headers

    def post(self, request):
        data = request.data
        try:
            transaction = ParkingTransaction.objects.get(id=data["parking_transaction_id"])
            transaction.payment_status = data["status"]
            transaction.mpesa_transaction_id = data.get("mpesa_transaction_id")
            if data["status"] == "PAID":
                transaction.status = "completed"
            elif data["status"] == "FAILED":
                transaction.status = "failed"
            transaction.save()
            logger.info(f"Payment status updated for transaction {transaction.id}: {data['status']}")
            return Response({"status": "success", "message": "Status updated"}, status=status.HTTP_200_OK)
        except ParkingTransaction.DoesNotExist:
            logger.error(f"Transaction not found for payment callback: {data.get('parking_transaction_id')}")
            return Response(
                {"status": "error", "message": "Parking transaction not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error processing payment callback: {str(e)}")
            return Response(
                {"status": "error", "message": "An unexpected error occurred", "details": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class CheckNumberPlate(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        number_plate = request.data.get('number_plate')
        parking_space_id = request.data.get('parking_space_id')

        logger.info(f"Checking number plate {number_plate} for user {request.user.email}")

        if not number_plate or not parking_space_id:
            logger.error(f"Missing number plate or parking space ID for user {request.user.email}")
            return Response(
                {'status': 'error', 'message': 'Number plate and parking space ID are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        number_plate = number_plate.upper().replace(' ', '')
        if not re.match(r'^[A-Z0-9]{1,8}$', number_plate):
            logger.error(f"Invalid number plate format for user {request.user.email}: {number_plate}")
            return Response(
                {'status': 'error', 'message': 'Invalid number plate format. Use up to 8 alphanumeric characters'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            with transaction.atomic():
                parking_space = ParkingSpace.objects.select_for_update().get(id=parking_space_id)
                if parking_space.is_occupied:
                    logger.warning(f"Parking space {parking_space_id} already occupied for user {request.user.email}")
                    return Response(
                        {'status': 'error', 'message': 'Parking space already occupied'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                try:
                    car = Car.objects.select_related('user').get(number_plate__iexact=number_plate, user=request.user)
                    if car.user.balance < settings.MINIMUM_PARKING_BALANCE:
                        logger.warning(f"Insufficient balance for user {request.user.email}: {car.user.balance}")
                        return Response(
                            {'status': 'error', 'message': f'Insufficient balance. Minimum required: {settings.MINIMUM_PARKING_BALANCE}'},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    parking_space.is_occupied = True
                    parking_space.save()

                    transaction = ParkingTransaction.objects.create(
                        car=car,
                        parking_space=parking_space,
                        entry_time=timezone.now(),
                        status='ongoing',
                        payment_status='PENDING',
                        created_at=timezone.now()
                    )
                    logger.info(f"Transaction created for user {request.user.email}: {transaction.id}")
                    return Response({
                        'status': 'success',
                        'message': 'Vehicle registered, entry logged',
                        'transaction': ParkingTransactionSerializer(transaction).data
                    }, status=status.HTTP_201_CREATED)

                except Car.DoesNotExist:
                    alert = Alert.objects.create(
                        parking_space=parking_space,
                        number_plate=number_plate,
                        description=f"Unregistered car with number plate {number_plate}",
                        status='unresolved'
                    )
                    logger.warning(f"Unregistered vehicle {number_plate} detected, alert created")
                    return Response({
                        'status': 'alert',
                        'message': 'Unregistered vehicle, alert logged',
                        'alert': AlertSerializer(alert).data
                    }, status=status.HTTP_201_CREATED)

        except ParkingSpace.DoesNotExist:
            logger.error(f"Parking space not found: {parking_space_id}")
            return Response(
                {'status': 'error', 'message': 'Parking space not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error checking number plate for user {request.user.email}: {str(e)}")
            return Response(
                {'status': 'error', 'message': 'An unexpected error occurred', 'details': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class ExitVehicle(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        transaction_id = request.data.get('transaction_id')

        logger.info(f"Processing exit for transaction {transaction_id} by user {request.user.email}")

        if not transaction_id:
            logger.error(f"Missing transaction ID for user {request.user.email}")
            return Response(
                {'status': 'error', 'message': 'Transaction ID is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            with transaction.atomic():
                transaction = ParkingTransaction.objects.select_related('car__user', 'parking_space').get(
                    id=transaction_id, car__user=request.user, status='ongoing'
                )
                transaction.exit_time = timezone.now()
                transaction.duration = transaction.exit_time - transaction.entry_time
                transaction.fee = transaction.calculate_fee()  # Assumes calculate_fee method in model
                transaction.status = 'completed'
                transaction.payment_status = 'PENDING'
                transaction.parking_space.is_occupied = False
                transaction.parking_space.save()
                transaction.save()

                # Normalize phone number for payment payload
                stored_phone = transaction.car.user.phone_number
                if stored_phone.startswith('0'):
                    normalized_phone = '254' + stored_phone[1:]
                else:
                    normalized_phone = stored_phone

                # Initiate payment
                payment_payload = {
                    "order_id": f"park-{transaction.id}",
                    "user_id": str(transaction.car.user.id),
                    "amount": f"{transaction.fee:.2f}",
                    "client_till_number": settings.CLIENT_TILL_NUMBER,
                    "phone_number": normalized_phone
                }

                logger.info(f"Payment payload for transaction {transaction.id}: {payment_payload}")

                response = requests.post(
                    f"{settings.PAYMENTS_API_URL}/api/v1/payments/process/",
                    json=payment_payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )

                if response.status_code != 201:
                    try:
                        error_json = response.json()
                    except ValueError:
                        error_json = response.text
                    logger.error(f"Payment initiation failed for transaction {transaction.id}: {error_json}")
                    return Response({
                        "status": "error",
                        "message": "Failed to initiate payment",
                        "details": error_json
                    }, status=response.status_code)

                logger.info(f"Exit processed for transaction {transaction.id}")
                return Response({
                    "status": "success",
                    "message": "Exit processed. Payment initiation sent.",
                    "transaction": ParkingTransactionSerializer(transaction).data
                }, status=status.HTTP_200_OK)

        except ParkingTransaction.DoesNotExist:
            logger.error(f"Transaction not found or unauthorized: {transaction_id} for user {request.user.email}")
            return Response(
                {'status': 'error', 'message': 'Transaction not found or not authorized'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error processing exit for transaction {transaction_id}: {str(e)}")
            return Response(
                {'status': 'error', 'message': 'An unexpected error occurred', 'details': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class TransactionsAPIView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ParkingTransactionSerializer

    def get_queryset(self):
        logger.info(f"Retrieving transactions for user {self.request.user.email}")
        return ParkingTransaction.objects.select_related('car__user', 'parking_space').filter(
            car__user=self.request.user
        ).order_by('-created_at')

class SupportTicketListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tickets = SupportTicket.objects.filter(user=request.user)
        logger.info(f"Support tickets retrieved for user {request.user.email}")
        return Response(SupportTicketSerializer(tickets, many=True).data, status=status.HTTP_200_OK)

    def post(self, request):
        data = request.data
        data['user'] = request.user.id
        serializer = SupportTicketSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Support ticket created for user {request.user.email}: {data.get('subject')}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.error(f"Support ticket creation failed for user {request.user.email}: {serializer.errors}")
        return Response(
            {'status': 'error', 'message': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
