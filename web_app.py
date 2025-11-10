"""
Event Ticketing System - Web Application
Single-file Flask application with embedded HTML templates
"""

import json
import csv
import os
import re
import hashlib
import uuid
from datetime import datetime
from collections import deque
from typing import Optional, Dict, List, Tuple, Any
from functools import wraps

from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for

# ============================================================================
# CONSTANTS
# ============================================================================

DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
EVENT_FILE = os.path.join(DATA_DIR, "event.json")
TICKETS_FILE = os.path.join(DATA_DIR, "tickets.json")
TRANSACTIONS_FILE = "transactions.csv"
ADMIN_EMAIL = "admin@eventtickets.com"
ADMIN_DEFAULT_PASSWORD = "admin123"

# ============================================================================
# DATA STRUCTURES
# ============================================================================

class PriorityQueue:
    """
    Priority Queue implementation for VIP ticket requests.
    VIP tickets are processed with higher priority than regular tickets.
    Uses a list-based approach with priority levels.
    """
    
    def __init__(self):
        self.queue = []
    
    def enqueue(self, item: Any, priority: int = 0):
        """
        Add an item to the queue with a given priority.
        Higher priority values are processed first.
        
        Time Complexity: O(n) where n is the queue size
        Space Complexity: O(1)
        """
        self.queue.append((priority, item))
        self.queue.sort(key=lambda x: -x[0])
    
    def dequeue(self) -> Optional[Any]:
        """
        Remove and return the highest priority item.
        
        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        if self.is_empty():
            return None
        return self.queue.pop(0)[1]
    
    def peek(self) -> Optional[Any]:
        """View the highest priority item without removing it."""
        if self.is_empty():
            return None
        return self.queue[0][1]
    
    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return len(self.queue) == 0
    
    def size(self) -> int:
        """Return the number of items in queue."""
        return len(self.queue)
    
    def clear(self):
        """Remove all items from queue."""
        self.queue.clear()


class Queue:
    """
    Standard FIFO Queue implementation for regular ticket requests.
    Uses deque for efficient operations on both ends.
    """
    
    def __init__(self):
        self.queue = deque()
    
    def enqueue(self, item: Any):
        """
        Add an item to the rear of the queue.
        
        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        self.queue.append(item)
    
    def dequeue(self) -> Optional[Any]:
        """
        Remove and return the front item.
        
        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        if self.is_empty():
            return None
        return self.queue.popleft()
    
    def peek(self) -> Optional[Any]:
        """View the front item without removing it."""
        if self.is_empty():
            return None
        return self.queue[0]
    
    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return len(self.queue) == 0
    
    def size(self) -> int:
        """Return the number of items in queue."""
        return len(self.queue)
    
    def clear(self):
        """Remove all items from queue."""
        self.queue.clear()


# ============================================================================
# VALIDATORS AND UTILITIES
# ============================================================================

class Validators:
    """Input validation utilities for user data."""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email format.
        Pattern: username@domain.extension
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """
        Validate phone number format.
        Accepts: 10 digits, with optional country code and formatting
        """
        cleaned = re.sub(r'[\s\-\(\)\+]', '', phone)
        return bool(re.match(r'^\d{10,15}$', cleaned))
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """
        Validate password strength.
        Requirements: At least 6 characters
        Returns: (is_valid, error_message)
        """
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        return True, ""
    
    @staticmethod
    def validate_name(name: str) -> bool:
        """Validate name (2-50 characters, letters and spaces only)."""
        return bool(re.match(r'^[a-zA-Z\s]{2,50}$', name))
    
    @staticmethod
    def normalize_phone(phone: str) -> str:
        """Normalize phone number by removing formatting."""
        return re.sub(r'[\s\-\(\)\+]', '', phone)


class PasswordHasher:
    """Utility for secure password hashing and verification."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using SHA-256 with salt.
        Note: In production, use bcrypt. Using SHA-256 to avoid external dependencies.
        """
        salt = uuid.uuid4().hex
        hashed = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}${hashed}"
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        try:
            salt, hash_value = hashed.split('$')
            computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return computed_hash == hash_value
        except:
            return False


# ============================================================================
# DATA MODELS
# ============================================================================

class User:
    """User data model with authentication information."""
    
    def __init__(self, user_id: str, first_name: str, last_name: str,
                 email: str, phone: str, password_hash: str, is_admin: bool = False):
        self.user_id = user_id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert user object to dictionary for JSON serialization."""
        return {
            'user_id': self.user_id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'phone': self.phone,
            'password_hash': self.password_hash,
            'is_admin': self.is_admin,
            'created_at': self.created_at
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'User':
        """Create user object from dictionary."""
        user = User(
            data['user_id'],
            data['first_name'],
            data['last_name'],
            data['email'],
            data['phone'],
            data['password_hash'],
            data.get('is_admin', False)
        )
        user.created_at = data.get('created_at', datetime.now().isoformat())
        return user
    
    def get_full_name(self) -> str:
        """Return user's full name."""
        return f"{self.first_name} {self.last_name}"


class Event:
    """Event data model with ticket configuration."""
    
    def __init__(self, event_id: str, name: str, vip_quantity: int,
                 vip_price: float, regular_quantity: int, regular_price: float):
        self.event_id = event_id
        self.name = name
        self.vip_quantity = vip_quantity
        self.vip_price = vip_price
        self.regular_quantity = regular_quantity
        self.regular_price = regular_price
        self.vip_sold = 0
        self.regular_sold = 0
        self.created_at = datetime.now().isoformat()
    
    def get_vip_available(self) -> int:
        """Get number of available VIP tickets."""
        return self.vip_quantity - self.vip_sold
    
    def get_regular_available(self) -> int:
        """Get number of available regular tickets."""
        return self.regular_quantity - self.regular_sold
    
    def to_dict(self) -> Dict:
        """Convert event object to dictionary."""
        return {
            'event_id': self.event_id,
            'name': self.name,
            'vip_quantity': self.vip_quantity,
            'vip_price': self.vip_price,
            'regular_quantity': self.regular_quantity,
            'regular_price': self.regular_price,
            'vip_sold': self.vip_sold,
            'regular_sold': self.regular_sold,
            'created_at': self.created_at
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'Event':
        """Create event object from dictionary."""
        event = Event(
            data['event_id'],
            data['name'],
            data['vip_quantity'],
            data['vip_price'],
            data['regular_quantity'],
            data['regular_price']
        )
        event.vip_sold = data.get('vip_sold', 0)
        event.regular_sold = data.get('regular_sold', 0)
        event.created_at = data.get('created_at', datetime.now().isoformat())
        return event


class Ticket:
    """Ticket data model representing a purchased ticket."""
    
    def __init__(self, ticket_id: str, user_id: str, event_id: str,
                 ticket_type: str, price: float):
        self.ticket_id = ticket_id
        self.user_id = user_id
        self.event_id = event_id
        self.ticket_type = ticket_type  # "VIP" or "Regular"
        self.price = price
        self.purchased_at = datetime.now().isoformat()
        self.status = "active"  # "active" or "cancelled"
    
    def to_dict(self) -> Dict:
        """Convert ticket object to dictionary."""
        return {
            'ticket_id': self.ticket_id,
            'user_id': self.user_id,
            'event_id': self.event_id,
            'ticket_type': self.ticket_type,
            'price': self.price,
            'purchased_at': self.purchased_at,
            'status': self.status
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'Ticket':
        """Create ticket object from dictionary."""
        ticket = Ticket(
            data['ticket_id'],
            data['user_id'],
            data['event_id'],
            data['ticket_type'],
            data['price']
        )
        ticket.purchased_at = data.get('purchased_at', datetime.now().isoformat())
        ticket.status = data.get('status', 'active')
        return ticket


# ============================================================================
# STORAGE MANAGER
# ============================================================================

class StorageManager:
    """Handles all file I/O operations for persistent data storage."""
    
    @staticmethod
    def initialize_storage():
        """Create data directory and initialize files if they don't exist."""
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR)
        
        if not os.path.exists(USERS_FILE):
            admin_user = User(
                user_id=str(uuid.uuid4()),
                first_name="Admin",
                last_name="User",
                email=ADMIN_EMAIL,
                phone="0000000000",
                password_hash=PasswordHasher.hash_password(ADMIN_DEFAULT_PASSWORD),
                is_admin=True
            )
            StorageManager.save_users({admin_user.user_id: admin_user.to_dict()})
        
        if not os.path.exists(EVENT_FILE):
            StorageManager.save_event(None)
        
        if not os.path.exists(TICKETS_FILE):
            StorageManager.save_tickets({})

        if not os.path.exists(TRANSACTIONS_FILE):
            with open(TRANSACTIONS_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'user_id', 'email', 'ticket_type',
                               'action', 'status', 'price', 'message'])
    
    @staticmethod
    def load_users() -> Dict[str, Dict]:
        """Load all users from JSON file."""
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    @staticmethod
    def save_users(users: Dict[str, Dict]):
        """Save all users to JSON file."""
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    
    @staticmethod
    def load_event() -> Optional[Dict]:
        """Load event configuration from JSON file."""
        try:
            with open(EVENT_FILE, 'r') as f:
                data = json.load(f)
                return data if data else None
        except:
            return None
    
    @staticmethod
    def save_event(event: Optional[Dict]):
        """Save event configuration to JSON file."""
        with open(EVENT_FILE, 'w') as f:
            json.dump(event, f, indent=2)
    
    @staticmethod
    def load_tickets() -> Dict[str, Dict]:
        """Load all tickets from JSON file."""
        try:
            with open(TICKETS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    @staticmethod
    def save_tickets(tickets: Dict[str, Dict]):
        """Save all tickets to JSON file."""
        with open(TICKETS_FILE, 'w') as f:
            json.dump(tickets, f, indent=2)


# ============================================================================
# SERVICES
# ============================================================================

class AuthService:
    """Handles user authentication and registration."""
    
    def __init__(self):
        self.users = StorageManager.load_users()
    
    def register_user(self, first_name: str, last_name: str, email: str,
                     phone: str, password: str, password_confirm: str) -> Tuple[bool, str, Optional[User]]:
        """
        Register a new user with validation.
        Returns: (success, message, user_object)
        """
        if not Validators.validate_name(first_name):
            return False, "Invalid first name (2-50 letters only)", None
        
        if not Validators.validate_name(last_name):
            return False, "Invalid last name (2-50 letters only)", None
        
        if not Validators.validate_email(email):
            return False, "Invalid email format", None
        
        if not Validators.validate_phone(phone):
            return False, "Invalid phone number (10-15 digits)", None
        
        is_valid, error = Validators.validate_password(password)
        if not is_valid:
            return False, error, None
        
        if password != password_confirm:
            return False, "Passwords do not match", None
        
        normalized_phone = Validators.normalize_phone(phone)
        for user_data in self.users.values():
            if user_data['email'].lower() == email.lower():
                return False, "Email already registered", None
            if Validators.normalize_phone(user_data['phone']) == normalized_phone:
                return False, "Phone number already registered", None
        
        user = User(
            user_id=str(uuid.uuid4()),
            first_name=first_name.strip(),
            last_name=last_name.strip(),
            email=email.lower().strip(),
            phone=normalized_phone,
            password_hash=PasswordHasher.hash_password(password),
            is_admin=False
        )
        
        self.users[user.user_id] = user.to_dict()
        StorageManager.save_users(self.users)
        
        return True, "Registration successful!", user
    
    def login(self, identifier: str, password: str) -> Tuple[bool, str, Optional[User]]:
        """
        Login user with email/phone and password.
        Returns: (success, message, user_object)
        """
        normalized_identifier = identifier.lower().strip()
        is_email = Validators.validate_email(normalized_identifier)
        
        if not is_email:
            normalized_identifier = Validators.normalize_phone(identifier)
        
        for user_data in self.users.values():
            if is_email:
                if user_data['email'].lower() == normalized_identifier:
                    if PasswordHasher.verify_password(password, user_data['password_hash']):
                        return True, "Login successful!", User.from_dict(user_data)
                    else:
                        return False, "Invalid password", None
            else:
                if Validators.normalize_phone(user_data['phone']) == normalized_identifier:
                    if PasswordHasher.verify_password(password, user_data['password_hash']):
                        return True, "Login successful!", User.from_dict(user_data)
                    else:
                        return False, "Invalid password", None
        
        return False, "Account not found", None


class TicketService:
    """Handles ticket purchasing, cancellation, and queue management."""
    
    def __init__(self):
        self.vip_queue = PriorityQueue()
        self.regular_queue = Queue()
        self.tickets = StorageManager.load_tickets()
        self.event = None
        self._load_event()
    
    def _load_event(self):
        """Load event configuration."""
        event_data = StorageManager.load_event()
        if event_data:
            self.event = Event.from_dict(event_data)
    
    def create_event(self, name: str, vip_quantity: int, vip_price: float,
                    regular_quantity: int, regular_price: float) -> Tuple[bool, str]:
        """Create a new event (admin only)."""
        try:
            if vip_quantity < 0 or regular_quantity < 0:
                return False, "Quantities must be non-negative"
            
            if vip_price < 0 or regular_price < 0:
                return False, "Prices must be non-negative"
            
            self.event = Event(
                event_id=str(uuid.uuid4()),
                name=name.strip(),
                vip_quantity=vip_quantity,
                vip_price=vip_price,
                regular_quantity=regular_quantity,
                regular_price=regular_price
            )
            
            StorageManager.save_event(self.event.to_dict())
            return True, "Event created successfully!"
        except Exception as e:
            return False, f"Error creating event: {str(e)}"
    
    def get_event(self) -> Optional[Event]:
        """Get current event."""
        return self.event
    
    def purchase_ticket(self, user: User, ticket_type: str) -> Tuple[bool, str, Optional[Ticket]]:
        """
        Purchase a ticket for a user.
        Adds request to appropriate queue and processes immediately.
        Returns: (success, message, ticket_object)
        """
        if not self.event:
            return False, "No event configured", None
        
        ticket_type = ticket_type.upper()
        if ticket_type not in ["VIP", "REGULAR"]:
            return False, "Invalid ticket type", None
        
        if ticket_type == "VIP":
            if self.event.get_vip_available() <= 0:
                return False, "No VIP tickets available", None
            price = self.event.vip_price
        else:
            if self.event.get_regular_available() <= 0:
                return False, "No Regular tickets available", None
            price = self.event.regular_price
        
        ticket = Ticket(
            ticket_id=str(uuid.uuid4()),
            user_id=user.user_id,
            event_id=self.event.event_id,
            ticket_type=ticket_type,
            price=price
        )
        
        if ticket_type == "VIP":
            self.event.vip_sold += 1
        else:
            self.event.regular_sold += 1
        
        self.tickets[ticket.ticket_id] = ticket.to_dict()
        StorageManager.save_tickets(self.tickets)
        StorageManager.save_event(self.event.to_dict())
        
        return True, f"{ticket_type} ticket purchased successfully!", ticket
    
    def cancel_ticket(self, ticket_id: str, user: User) -> Tuple[bool, str]:
        """
        Cancel a ticket and free up the spot.
        Returns: (success, message)
        """
        if ticket_id not in self.tickets:
            return False, "Ticket not found"
        
        ticket_data = self.tickets[ticket_id]
        
        if ticket_data['user_id'] != user.user_id:
            return False, "You don't own this ticket"
        
        if ticket_data['status'] == 'cancelled':
            return False, "Ticket already cancelled"
        
        ticket_data['status'] = 'cancelled'
        self.tickets[ticket_id] = ticket_data
        
        if ticket_data['ticket_type'] == "VIP":
            self.event.vip_sold -= 1
        else:
            self.event.regular_sold -= 1
        
        StorageManager.save_tickets(self.tickets)
        StorageManager.save_event(self.event.to_dict())
        
        return True, "Ticket cancelled successfully. Refund will be processed."
    
    def get_user_tickets(self, user: User) -> List[Ticket]:
        """Get all active tickets for a user."""
        user_tickets = []
        for ticket_data in self.tickets.values():
            if ticket_data['user_id'] == user.user_id and ticket_data['status'] == 'active':
                user_tickets.append(Ticket.from_dict(ticket_data))
        return user_tickets
    
    def get_sales_summary(self) -> Dict:
        """Get sales summary for admin."""
        if not self.event:
            return {}
        
        return {
            'event_name': self.event.name,
            'vip_sold': self.event.vip_sold,
            'vip_available': self.event.get_vip_available(),
            'vip_total': self.event.vip_quantity,
            'vip_revenue': self.event.vip_sold * self.event.vip_price,
            'regular_sold': self.event.regular_sold,
            'regular_available': self.event.get_regular_available(),
            'regular_total': self.event.regular_quantity,
            'regular_revenue': self.event.regular_sold * self.event.regular_price,
            'total_tickets_sold': self.event.vip_sold + self.event.regular_sold,
            'total_revenue': (self.event.vip_sold * self.event.vip_price) + 
                           (self.event.regular_sold * self.event.regular_price)
        }


class TransactionService:
    """Handles logging of all transactions to CSV file."""
    
    @staticmethod
    def log_transaction(user_id: str, email: str, ticket_type: str,
                       action: str, status: str, price: float, message: str):
        """
        Log a transaction to the CSV file.
        
        Parameters:
        - user_id: User identifier
        - email: User email
        - ticket_type: "VIP" or "Regular"
        - action: "purchase", "cancel", etc.
        - status: "success" or "failed"
        - price: Transaction amount
        - message: Additional information
        """
        try:
            with open(TRANSACTIONS_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(),
                    user_id,
                    email,
                    ticket_type,
                    action,
                    status,
                    f"${price:.2f}",
                    message
                ])
        except Exception as e:
            print(f"Warning: Could not log transaction: {e}")


# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

app = Flask(__name__)
app.secret_key = 'event-ticketing-system-secret-key-2025'

# Initialize services
auth_service = AuthService()
ticket_service = TicketService()


# ============================================================================
# AUTHENTICATION HELPERS
# ============================================================================

def get_current_user() -> Optional[User]:
    """Get current user from session."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    
    users = StorageManager.load_users()
    user_data = users.get(user_id)
    if user_data:
        return User.from_dict(user_data)
    return None


def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin access for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_admin:
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# HTML TEMPLATES
# ============================================================================

# Landing Page HTML
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="og:title" content="Book Your Tickets" />
  <meta name="description" content="Book Your Tickets with Omari's Ticketing System" />
  <title>Book Your Tickets</title>
  <link rel="stylesheet" href="https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/themes/smoothness/jquery-ui.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/motion-ui@1.2.3/dist/motion-ui.min.css" />
  <link href="https://www.letsjive.io/includes/css/app.css?1762451922" rel="stylesheet" type="text/css">
  <script language="javascript" type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js"></script>
  <script language="javascript" type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js"></script>
  <script src="https://kit.fontawesome.com/3c5669a9ad.js" crossorigin="anonymous"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/ScrollTrigger.min.js"></script>
  <link rel="icon" href="https://www.letsjive.io/favicon.png" type="image/png" />
</head>
<body class="relative">
    <div class="flex flex-col min-h-screen h-full mx-auto overflow-hidden relative">
        <header class="relative">
    <nav class="border-gray-200 px-4 lg:px-6 py-4 dark:bg-gray-800 relative z-50 gsap-nav">
        <div class="grid grid-cols-3 items-center mx-auto max-w-screen-xl">
            <div class="flex justify-start items-center col-span-1 gsap-nav-left">
                <a href="/signin" class="text-primary-900 bg-white border border-gray-200 hover:bg-jive-yellow focus:ring-4 focus:ring-jive-teal-20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 focus:outline-none md:hidden gsap-btn">Admin</a>
            </div>
            <div class="flex items-center justify-center gsap-logo">
                <a href="/" class="inline-block group/logo">
                    <img src="https://ik.imagekit.io/dr5fryhth/Adobe%20Express%20-%20file.png?updatedAt=1762746280976" class="h-8 md:h-10 group-hover/logo:hidden" alt="Jive" />
                    <img src="https://ik.imagekit.io/dr5fryhth/Adobe%20Express%20-%20file.png?updatedAt=1762746280976" class="h-8 md:h-10 hidden group-hover/logo:inline-block" alt="Jive" />
                </a>
            </div>
            <div class="flex justify-end items-center col-span-1 gsap-nav-right">
                <a href="/signin" class="text-primary-900 bg-white border border-gray-200 hover:bg-jive-yellow focus:ring-4 focus:ring-jive-teal-20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 focus:outline-none hidden md:flex gsap-btn">Admin</a>
                <a href="/signin" class="text-white bg-primary-900 hover:bg-jive-blue focus:ring-4 focus:ring-jive-teal/20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 ml-2 focus:outline-none gsap-btn">Sign In</a>
            </div>
        </div>
    </nav>
</header>
        <div class="flex-grow">
            <div class="absolute top-0 bottom-0 mx-auto left-1/2 transform -translate-x-1/2 z-0 w-full md:w-[1200px] lg:w-[1600px] max-w-screen gsap-shapes">
  <img src="https://www.letsjive.io/images/marketing/home-shapes-full.svg" class="hidden lg:block w-full h-full object-cover" alt="Shapes" />
  <img src="https://www.letsjive.io/images/marketing/home-shapes-tablet.svg" class="hidden md:block w-full h-full object-cover" alt="Shapes" />
  <img src="https://www.letsjive.io/images/marketing/home-shapes-mobile.svg" class="md:hidden w-full h-full object-cover" alt="Shapes" />
</div>
<section class="relative">
  <div class="max-w-screen-xl px-6 py-8 mx-auto lg:px-6 sm:py-16 lg:py-24">
    <div class="text-center">
      <div class="max-w-xl mx-auto">
        <h1 class="text-5xl font-extrabold leading-none tracking-tight text-primary-900 dark:text-white md:text-7xl mb-6 gsap-hero-title">
        Ticket Booking Made Simple</h1>
        <p class="mt-4 text-lg md:text-xl font-normal text-primary-500 md:max-w-3xl md:mx-auto mb-6 md:mb-10 gsap-hero-text">No more standing in long queues, stressing over ticket sales and missing out on your favorite events. <br> Get it all with this simple ticketing system!</p>
        <a href="/signin" class="text-white bg-primary-900 hover:bg-jive-green focus:ring-4 focus:outline-none focus:ring-jive-teal/30 font-semibold rounded-full text-xl px-12 py-4 text-center dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 inline-block transition gsap-hero-btn">Book Your Tickets Now</a>
      </div>
    </div>
  </div>
  <div class="mt-8 sm:mt-16">
    <div class="relative mx-auto max-w-[800px] w-auto gsap-hero-image">
      <img src="https://ik.imagekit.io/dr5fryhth/Adobe%20Express%20-%20file%20(1).png?updatedAt=1762746825436" class="w-full" alt="Jive phones" />
    </div>
  </div>
</section>
<section class="relative">
  <div class="py-8 px-6 mx-auto max-w-screen-xl text-center sm:py-16 lg:px-6 lg:py-24">
      <h2 class="mb-4 text-4xl max-w-[200px] mx-auto md:max-w-full tracking-tight font-extrabold text-primary-900 gsap-features-title">Here's how it works</h2>
      <p class="text-primary-500 font-normal text-lg md:text-xl gsap-features-subtitle">More booking, less stressing</p>
      <div class="my-8 lg:my-12 gap-8 flex flex-col md:flex-row flex-wrap md:gap-12 justify-center content-center justify-items-center">
          <div class="max-w-[310px] gsap-feature-card">
              <img src="https://www.letsjive.io/images/marketing/feature-1.svg" class="mx-auto mb-4 w-12 h-12 gsap-feature-icon" alt="Step 1" />
              <h3 class="mb-2 text-2xl font-bold gsap-feature-title">Create an account/Log In</h3>
              <p class="mb-4 text-primary-500 text-lg gsap-feature-text">Enter the system with the appropriate credentials in one easy setup.</p>
          </div>
          <div class="max-w-[310px] gsap-feature-card">
              <img src="https://www.letsjive.io/images/marketing/feature-2.svg" class="mx-auto mb-4 w-12 h-12 gsap-feature-icon" alt="Step 2" />
              <h3 class="mb-2 text-2xl font-bold gsap-feature-title">Select a Ticket Type</h3>
              <p class="mb-4 text-primary-500 text-lg gsap-feature-text">Choose your type of ticket; VIP or Regular and pay in one easy step</p>
          </div>
          <div class="max-w-[310px] gsap-feature-card">
              <img src="https://www.letsjive.io/images/marketing/feature-3.svg" class="mx-auto mb-4 w-12 h-12 gsap-feature-icon" alt="Step 3" />
              <h3 class="mb-2 text-2xl font-bold gsap-feature-title">Enjoy The Show</h3>
              <p class="mb-4 text-primary-500 text-lg gsap-feature-text">You are good to go. Have Fun!</p>
          </div>
      </div>
      <a href="/signin" class="text-white bg-primary-900 hover:bg-jive-pink focus:ring-4 focus:outline-none focus:ring-jive-teal/30 font-semibold rounded-full text-xl px-12 py-4 text-center dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 transition inline-block gsap-features-btn">Get Your Ticket</a>
  </div>
</section>        </div>
        <footer class="p-4 md:p-8 lg:p-10 relative">
  <div class="mx-auto max-w-screen-xl text-center">
      <div class="flex items-center justify-center gsap-footer-title">
        <h3>Event Ticketing System</h3>
      </div>
      <span class="text-sm text-gray-500 sm:text-center gsap-footer-text">&copy; 2025 <a href="#" class="hover:text-jive-teal transition">Event Tickets</a> by <a href="https://omaribrightswe.dpdns.org/" class="hover:text-jive-pink transition" target="_blank"><u>Bright Omari Owusu</u></a></span>
  </div>
</footer>    </div>
    <div id="alert_modal" tabindex="-1" aria-hidden="true" class="fixed top-0 left-0 right-0 z-50 hidden w-full p-4 overflow-x-hidden overflow-y-auto md:inset-0 h-[calc(100%-1rem)] md:h-full" role="dialog">
    <div class="relative w-full h-full max-w-lg md:h-auto">
        <div class="relative bg-white text-gray-900 rounded-lg shadow dark:bg-gray-700 dark:text-white">
            <div class="flex items-middle justify-between py-4 px-6 border-b rounded-t dark:border-gray-600">
                <h3 class="text-xl font-semibold alert-headline">Alert!</h3>
                <button type="button" class="text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-gray-600 dark:hover:text-white alert-button-close">
                    <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg>
                    <span class="sr-only">Close modal</span>
                </button>
            </div>
            <div class="p-6">
                <p class="text-base leading-relaxed alert-message">This is an alert...</p>
            </div>
            <div class="p-6 space-x-2 text-center">
                <button type="button" class="text-white bg-primary-700 hover:bg-primary-800 focus:ring-4 focus:outline-none focus:ring-primary-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 alert-button-confirm w-full">OK</button>
            </div>
        </div>
    </div>
</div>
<button data-modal-target="alert_modal" style="display:none;"></button>
<script type="text/javascript">
var AlertModal = (function(settings) {
    return {
        headline: settings.headline,
        message: settings.message,
        buttons: settings.buttons,
        _modal: null,
        open: function() {
            var modal = $('#alert_modal');
            if (this.headline != undefined) {
                $(modal).find('.alert-headline').html(this.headline);
            }
            if (this.message != undefined) {
                $(modal).find('.alert-message').html(this.message);
            }
            if (this.buttons != undefined) {
                if (this.buttons.confirm != undefined) {
                    $(modal).find('.alert-button-confirm').html(this.buttons.confirm);
                }
            }
            var scope = this;
            $(modal).find('.alert-button-confirm').unbind('click').click(function(e) {
                scope.confirm();
            });
            $(modal).find('.alert-button-close').unbind('click').click(function(e) {
                scope.close();
            });
            this._modal = new Modal(document.getElementById('alert_modal'));
            this._modal.show();
        },
        close: function() {
            this._modal.hide();
        },
        confirm: function() {
            if (settings.confirm != undefined) {
              settings.confirm();
            }
            this.close();
        }
    };
});
</script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/flowbite/1.6.4/flowbite.min.js"></script>
<script type="text/javascript" src="https://www.letsjive.io/includes/js/utm.js"></script>
<script type="text/javascript">
gsap.registerPlugin(ScrollTrigger);
gsap.set('.gsap-nav-left', { opacity: 0, x: -50 });
gsap.set('.gsap-logo', { opacity: 0, scale: 0.8 });
gsap.set('.gsap-nav-right', { opacity: 0, x: 50 });
gsap.set('.gsap-shapes', { opacity: 0, scale: 1.1 });
gsap.set('.gsap-hero-title', { opacity: 0, y: 50 });
gsap.set('.gsap-hero-text', { opacity: 0, y: 30 });
gsap.set('.gsap-hero-btn', { opacity: 0, y: 20, scale: 0.9 });
gsap.set('.gsap-hero-image', { opacity: 0, y: 80, scale: 0.95 });
gsap.set('.gsap-features-title', { opacity: 0, y: 30 });
gsap.set('.gsap-features-subtitle', { opacity: 0, y: 20 });
gsap.set('.gsap-feature-card', { opacity: 0, y: 50, scale: 0.9 });
gsap.set('.gsap-features-btn', { opacity: 0, y: 20 });
gsap.set('.gsap-footer-title', { opacity: 0, y: 20 });
gsap.set('.gsap-footer-text', { opacity: 0, y: 10 });
gsap.timeline({ delay: 0.2 })
    .to('.gsap-nav-left', { opacity: 1, x: 0, duration: 0.6, ease: 'power3.out' })
    .to('.gsap-logo', { opacity: 1, scale: 1, duration: 0.5, ease: 'back.out(1.7)' }, '-=0.3')
    .to('.gsap-nav-right', { opacity: 1, x: 0, duration: 0.6, ease: 'power3.out' }, '-=0.5');
gsap.to('.gsap-shapes', {
    opacity: 1,
    scale: 1,
    duration: 1.5,
    ease: 'power2.out',
    delay: 0.3
});
gsap.timeline({ delay: 0.5 })
    .to('.gsap-hero-title', {
        opacity: 1,
        y: 0,
        duration: 0.8,
        ease: 'power3.out'
    })
    .to('.gsap-hero-text', {
        opacity: 1,
        y: 0,
        duration: 0.7,
        ease: 'power2.out'
    }, '-=0.4')
    .to('.gsap-hero-btn', {
        opacity: 1,
        y: 0,
        scale: 1,
        duration: 0.6,
        ease: 'back.out(1.4)'
    }, '-=0.3')
    .to('.gsap-hero-image', {
        opacity: 1,
        y: 0,
        scale: 1,
        duration: 1,
        ease: 'power2.out'
    }, '-=0.2');
gsap.timeline({
    scrollTrigger: {
        trigger: '.gsap-features-title',
        start: 'top 80%',
        end: 'top 50%',
        toggleActions: 'play none none none'
    }
})
    .to('.gsap-features-title', {
        opacity: 1,
        y: 0,
        duration: 0.7,
        ease: 'power2.out'
    })
    .to('.gsap-features-subtitle', {
        opacity: 1,
        y: 0,
        duration: 0.6,
        ease: 'power2.out'
    }, '-=0.3')
    .to('.gsap-feature-card', {
        opacity: 1,
        y: 0,
        scale: 1,
        duration: 0.6,
        stagger: 0.15,
        ease: 'back.out(1.2)'
    }, '-=0.2')
    .to('.gsap-features-btn', {
        opacity: 1,
        y: 0,
        duration: 0.5,
        ease: 'power2.out'
    }, '-=0.3');
document.querySelectorAll('.gsap-feature-card').forEach(card => {
    card.addEventListener('mouseenter', function() {
        gsap.to(this, {
            scale: 1.05,
            y: -10,
            duration: 0.3,
            ease: 'power2.out'
        });
        gsap.to(this.querySelector('.gsap-feature-icon'), {
            rotation: 360,
            scale: 1.2,
            duration: 0.5,
            ease: 'back.out(1.7)'
        });
    });
    card.addEventListener('mouseleave', function() {
        gsap.to(this, {
            scale: 1,
            y: 0,
            duration: 0.3,
            ease: 'power2.out'
        });
        gsap.to(this.querySelector('.gsap-feature-icon'), {
            rotation: 0,
            scale: 1,
            duration: 0.3,
            ease: 'power2.out'
        });
    });
});
document.querySelectorAll('.gsap-btn, .gsap-hero-btn, .gsap-features-btn').forEach(btn => {
    btn.addEventListener('mouseenter', function() {
        gsap.to(this, {
            scale: 1.05,
            y: -2,
            duration: 0.2,
            ease: 'power2.out'
        });
    });
    btn.addEventListener('mouseleave', function() {
        gsap.to(this, {
            scale: 1,
            y: 0,
            duration: 0.2,
            ease: 'power2.out'
        });
    });
});
function animateFooter() {
    gsap.to('.gsap-footer-title', {
        opacity: 1,
        y: 0,
        duration: 0.6,
        ease: 'power2.out'
    });
    gsap.to('.gsap-footer-text', {
        opacity: 1,
        y: 0,
        duration: 0.5,
        ease: 'power2.out',
        delay: 0.2
    });
}
ScrollTrigger.create({
    trigger: 'footer',
    start: 'top 90%',
    onEnter: animateFooter,
    once: true
});
if (document.querySelector('.gsap-logo a')) {
    document.querySelector('.gsap-logo a').addEventListener('mouseenter', function() {
        gsap.to(this, {
            scale: 1.1,
            rotation: 5,
            duration: 0.3,
            ease: 'back.out(1.7)'
        });
    });
    document.querySelector('.gsap-logo a').addEventListener('mouseleave', function() {
        gsap.to(this, {
            scale: 1,
            rotation: 0,
            duration: 0.3,
            ease: 'power2.out'
        });
    });
}
</script>
</body>
</html>
"""


# Sign-In Page HTML
SIGNIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In - Event Ticketing System</title>
  <link href="https://www.letsjive.io/includes/css/app.css?1762451922" rel="stylesheet" type="text/css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/flowbite/1.6.4/flowbite.min.js"></script>
</head>
<body class="relative">
    <div class="flex flex-col min-h-screen h-full mx-auto overflow-hidden relative">
        <header class="relative">
    <nav class="border-gray-200 px-4 lg:px-6 py-4 dark:bg-gray-800 relative z-50">
        <div class="grid grid-cols-3 items-center mx-auto max-w-screen-xl">
            <div class="flex justify-start items-center col-span-1">
                <a href="/signin" class="text-primary-900 bg-white border border-gray-200 hover:bg-jive-yellow focus:ring-4 focus:ring-jive-teal-20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 focus:outline-none md:hidden">Admin</a>
            </div>
            <div class="flex items-center justify-center">
                <a href="/" class="inline-block">
                    <img src="https://ik.imagekit.io/dr5fryhth/Adobe%20Express%20-%20file.png?updatedAt=1762746280976" class="h-8 md:h-10" alt="Logo" />
                </a>
            </div>
            <div class="flex justify-end items-center col-span-1">
                <a href="/signin" class="text-primary-900 bg-white border border-gray-200 hover:bg-jive-yellow focus:ring-4 focus:ring-jive-teal-20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 focus:outline-none hidden md:flex">Admin</a>
                <a href="/signin" class="text-white bg-primary-900 hover:bg-jive-blue focus:ring-4 focus:ring-jive-teal/20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 ml-2 focus:outline-none">Sign In</a>
            </div>
        </div>
    </nav>
</header>
        <div class="flex-grow flex items-center justify-center py-12 px-4">
            <div class="max-w-md w-full">
                <div class="text-center mb-8">
                    <h1 class="text-4xl font-extrabold text-primary-900 mb-4">Sign In</h1>
                    <p class="text-primary-500">Enter your credentials to access your account</p>
                </div>
                <form id="signin-form" class="bg-white rounded-lg shadow-lg p-8">
                    <div class="mb-6">
                        <label for="identifier" class="block text-sm font-medium text-gray-700 mb-2">Email or Phone Number</label>
                        <input type="text" id="identifier" name="identifier" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent">
                    </div>
                    <div class="mb-6">
                        <label for="password" class="block text-sm font-medium text-gray-700 mb-2">Password</label>
                        <input type="password" id="password" name="password" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent">
                    </div>
                    <button type="submit" class="w-full text-white bg-primary-900 hover:bg-jive-green focus:ring-4 focus:outline-none focus:ring-jive-teal/30 font-semibold rounded-full text-lg px-6 py-3 transition">Sign In</button>
                    <div class="mt-4 text-center">
                        <a href="/signup" class="text-primary-600 hover:text-primary-800">Don't have an account? Sign up</a>
                    </div>
                </form>
            </div>
        </div>
        <footer class="p-4 md:p-8 lg:p-10 relative">
  <div class="mx-auto max-w-screen-xl text-center">
      <div class="flex items-center justify-center">
        <h3>Event Ticketing System</h3>
      </div>
      <span class="text-sm text-gray-500 sm:text-center">&copy; 2025 <a href="#" class="hover:text-jive-teal transition">Event Tickets</a> by <a href="https://omaribrightswe.dpdns.org/" class="hover:text-jive-pink transition" target="_blank"><u>Bright Omari Owusu</u></a></span>
  </div>
</footer>    </div>
    <div id="alert_modal" tabindex="-1" aria-hidden="true" class="fixed top-0 left-0 right-0 z-50 hidden w-full p-4 overflow-x-hidden overflow-y-auto md:inset-0 h-[calc(100%-1rem)] md:h-full" role="dialog">
    <div class="relative w-full h-full max-w-lg md:h-auto">
        <div class="relative bg-white text-gray-900 rounded-lg shadow dark:bg-gray-700 dark:text-white">
            <div class="flex items-middle justify-between py-4 px-6 border-b rounded-t dark:border-gray-600">
                <h3 class="text-xl font-semibold alert-headline">Alert!</h3>
                <button type="button" class="text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-gray-600 dark:hover:text-white alert-button-close">
                    <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg>
                    <span class="sr-only">Close modal</span>
                </button>
            </div>
            <div class="p-6">
                <p class="text-base leading-relaxed alert-message">This is an alert...</p>
            </div>
            <div class="p-6 space-x-2 text-center">
                <button type="button" class="text-white bg-primary-700 hover:bg-primary-800 focus:ring-4 focus:outline-none focus:ring-primary-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 alert-button-confirm w-full">OK</button>
            </div>
        </div>
    </div>
</div>
<button data-modal-target="alert_modal" style="display:none;"></button>
<script type="text/javascript">
var AlertModal = (function(settings) {
    return {
        headline: settings.headline,
        message: settings.message,
        buttons: settings.buttons,
        _modal: null,
        open: function() {
            var modal = $('#alert_modal');
            if (this.headline != undefined) {
                $(modal).find('.alert-headline').html(this.headline);
            }
            if (this.message != undefined) {
                $(modal).find('.alert-message').html(this.message);
            }
            if (this.buttons != undefined) {
                if (this.buttons.confirm != undefined) {
                    $(modal).find('.alert-button-confirm').html(this.buttons.confirm);
                }
            }
            var scope = this;
            $(modal).find('.alert-button-confirm').unbind('click').click(function(e) {
                scope.confirm();
            });
            $(modal).find('.alert-button-close').unbind('click').click(function(e) {
                scope.close();
            });
            this._modal = new Modal(document.getElementById('alert_modal'));
            this._modal.show();
        },
        close: function() {
            this._modal.hide();
        },
        confirm: function() {
            if (settings.confirm != undefined) {
              settings.confirm();
            }
            this.close();
        }
    };
});
$(document).ready(function() {
    $('#signin-form').submit(function(e) {
        e.preventDefault();
        var identifier = $('#identifier').val();
        var password = $('#password').val();
        
        $.ajax({
            url: '/api/login',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                identifier: identifier,
                password: password
            }),
            success: function(response) {
                if (response.success) {
                    AlertModal({
                        headline: 'Success!',
                        message: response.message,
                        buttons: { confirm: 'OK' },
                        confirm: function() {
                            window.location.href = response.redirect || '/dashboard';
                        }
                    }).open();
                } else {
                    AlertModal({
                        headline: 'Error',
                        message: response.message,
                        buttons: { confirm: 'OK' }
                    }).open();
                }
            },
            error: function() {
                AlertModal({
                    headline: 'Error',
                    message: 'An error occurred. Please try again.',
                    buttons: { confirm: 'OK' }
                }).open();
            }
        });
    });
});
</script>
</body>
</html>
"""


# Sign-Up Page HTML  
SIGNUP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign Up - Event Ticketing System</title>
  <link href="https://www.letsjive.io/includes/css/app.css?1762451922" rel="stylesheet" type="text/css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/flowbite/1.6.4/flowbite.min.js"></script>
</head>
<body class="relative">
    <div class="flex flex-col min-h-screen h-full mx-auto overflow-hidden relative">
        <header class="relative">
    <nav class="border-gray-200 px-4 lg:px-6 py-4 dark:bg-gray-800 relative z-50">
        <div class="grid grid-cols-3 items-center mx-auto max-w-screen-xl">
            <div class="flex justify-start items-center col-span-1">
                <a href="/signin" class="text-primary-900 bg-white border border-gray-200 hover:bg-jive-yellow focus:ring-4 focus:ring-jive-teal-20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 focus:outline-none md:hidden">Admin</a>
            </div>
            <div class="flex items-center justify-center">
                <a href="/" class="inline-block">
                    <img src="https://ik.imagekit.io/dr5fryhth/Adobe%20Express%20-%20file.png?updatedAt=1762746280976" class="h-8 md:h-10" alt="Logo" />
                </a>
            </div>
            <div class="flex justify-end items-center col-span-1">
                <a href="/signin" class="text-primary-900 bg-white border border-gray-200 hover:bg-jive-yellow focus:ring-4 focus:ring-jive-teal-20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 focus:outline-none hidden md:flex">Admin</a>
                <a href="/signin" class="text-white bg-primary-900 hover:bg-jive-blue focus:ring-4 focus:ring-jive-teal/20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 ml-2 focus:outline-none">Sign In</a>
            </div>
        </div>
    </nav>
</header>
        <div class="flex-grow flex items-center justify-center py-12 px-4">
            <div class="max-w-md w-full">
                <div class="text-center mb-8">
                    <h1 class="text-4xl font-extrabold text-primary-900 mb-4">Sign Up</h1>
                    <p class="text-primary-500">Create your account to get started</p>
                </div>
                <form id="signup-form" class="bg-white rounded-lg shadow-lg p-8">
                    <div class="mb-4">
                        <label for="first_name" class="block text-sm font-medium text-gray-700 mb-2">First Name</label>
                        <input type="text" id="first_name" name="first_name" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent">
                    </div>
                    <div class="mb-4">
                        <label for="last_name" class="block text-sm font-medium text-gray-700 mb-2">Last Name</label>
                        <input type="text" id="last_name" name="last_name" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent">
                    </div>
                    <div class="mb-4">
                        <label for="email" class="block text-sm font-medium text-gray-700 mb-2">Email</label>
                        <input type="email" id="email" name="email" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent">
                    </div>
                    <div class="mb-4">
                        <label for="phone" class="block text-sm font-medium text-gray-700 mb-2">Phone Number</label>
                        <input type="tel" id="phone" name="phone" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent">
                    </div>
                    <div class="mb-4">
                        <label for="password" class="block text-sm font-medium text-gray-700 mb-2">Password (min 6 characters)</label>
                        <input type="password" id="password" name="password" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent">
                    </div>
                    <div class="mb-6">
                        <label for="password_confirm" class="block text-sm font-medium text-gray-700 mb-2">Confirm Password</label>
                        <input type="password" id="password_confirm" name="password_confirm" required class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent">
                    </div>
                    <button type="submit" class="w-full text-white bg-primary-900 hover:bg-jive-green focus:ring-4 focus:outline-none focus:ring-jive-teal/30 font-semibold rounded-full text-lg px-6 py-3 transition">Sign Up</button>
                    <div class="mt-4 text-center">
                        <a href="/signin" class="text-primary-600 hover:text-primary-800">Already have an account? Sign in</a>
                    </div>
                </form>
            </div>
        </div>
        <footer class="p-4 md:p-8 lg:p-10 relative">
  <div class="mx-auto max-w-screen-xl text-center">
      <div class="flex items-center justify-center">
        <h3>Event Ticketing System</h3>
      </div>
      <span class="text-sm text-gray-500 sm:text-center">&copy; 2025 <a href="#" class="hover:text-jive-teal transition">Event Tickets</a> by <a href="https://omaribrightswe.dpdns.org/" class="hover:text-jive-pink transition" target="_blank"><u>Bright Omari Owusu</u></a></span>
  </div>
</footer>    </div>
    <div id="alert_modal" tabindex="-1" aria-hidden="true" class="fixed top-0 left-0 right-0 z-50 hidden w-full p-4 overflow-x-hidden overflow-y-auto md:inset-0 h-[calc(100%-1rem)] md:h-full" role="dialog">
    <div class="relative w-full h-full max-w-lg md:h-auto">
        <div class="relative bg-white text-gray-900 rounded-lg shadow dark:bg-gray-700 dark:text-white">
            <div class="flex items-middle justify-between py-4 px-6 border-b rounded-t dark:border-gray-600">
                <h3 class="text-xl font-semibold alert-headline">Alert!</h3>
                <button type="button" class="text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-gray-600 dark:hover:text-white alert-button-close">
                    <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg>
                    <span class="sr-only">Close modal</span>
                </button>
            </div>
            <div class="p-6">
                <p class="text-base leading-relaxed alert-message">This is an alert...</p>
            </div>
            <div class="p-6 space-x-2 text-center">
                <button type="button" class="text-white bg-primary-700 hover:bg-primary-800 focus:ring-4 focus:outline-none focus:ring-primary-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 alert-button-confirm w-full">OK</button>
            </div>
        </div>
    </div>
</div>
<button data-modal-target="alert_modal" style="display:none;"></button>
<script type="text/javascript">
var AlertModal = (function(settings) {
    return {
        headline: settings.headline,
        message: settings.message,
        buttons: settings.buttons,
        _modal: null,
        open: function() {
            var modal = $('#alert_modal');
            if (this.headline != undefined) {
                $(modal).find('.alert-headline').html(this.headline);
            }
            if (this.message != undefined) {
                $(modal).find('.alert-message').html(this.message);
            }
            if (this.buttons != undefined) {
                if (this.buttons.confirm != undefined) {
                    $(modal).find('.alert-button-confirm').html(this.buttons.confirm);
                }
            }
            var scope = this;
            $(modal).find('.alert-button-confirm').unbind('click').click(function(e) {
                scope.confirm();
            });
            $(modal).find('.alert-button-close').unbind('click').click(function(e) {
                scope.close();
            });
            this._modal = new Modal(document.getElementById('alert_modal'));
            this._modal.show();
        },
        close: function() {
            this._modal.hide();
        },
        confirm: function() {
            if (settings.confirm != undefined) {
              settings.confirm();
            }
            this.close();
        }
    };
});
$(document).ready(function() {
    $('#signup-form').submit(function(e) {
        e.preventDefault();
        var password = $('#password').val();
        var password_confirm = $('#password_confirm').val();
        
        if (password !== password_confirm) {
            AlertModal({
                headline: 'Error',
                message: 'Passwords do not match',
                buttons: { confirm: 'OK' }
            }).open();
            return;
        }
        
        $.ajax({
            url: '/api/register',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                first_name: $('#first_name').val(),
                last_name: $('#last_name').val(),
                email: $('#email').val(),
                phone: $('#phone').val(),
                password: password,
                password_confirm: password_confirm
            }),
            success: function(response) {
                if (response.success) {
                    AlertModal({
                        headline: 'Success!',
                        message: response.message + ' You can now sign in.',
                        buttons: { confirm: 'OK' },
                        confirm: function() {
                            window.location.href = '/signin';
                        }
                    }).open();
                } else {
                    AlertModal({
                        headline: 'Error',
                        message: response.message,
                        buttons: { confirm: 'OK' }
                    }).open();
                }
            },
            error: function() {
                AlertModal({
                    headline: 'Error',
                    message: 'An error occurred. Please try again.',
                    buttons: { confirm: 'OK' }
                }).open();
            }
        });
    });
});
</script>
</body>
</html>
"""


# Dashboard HTML (for regular users)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard - Event Ticketing System</title>
  <link href="https://www.letsjive.io/includes/css/app.css?1762451922" rel="stylesheet" type="text/css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/flowbite/1.6.4/flowbite.min.js"></script>
</head>
<body class="relative">
    <div class="flex flex-col min-h-screen h-full mx-auto overflow-hidden relative">
        <header class="relative">
    <nav class="border-gray-200 px-4 lg:px-6 py-4 dark:bg-gray-800 relative z-50">
        <div class="grid grid-cols-3 items-center mx-auto max-w-screen-xl">
            <div class="flex justify-start items-center col-span-1">
                <a href="/" class="text-primary-900 bg-white border border-gray-200 hover:bg-jive-yellow focus:ring-4 focus:ring-jive-teal-20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 focus:outline-none">Home</a>
            </div>
            <div class="flex items-center justify-center">
                <a href="/" class="inline-block">
                    <img src="https://ik.imagekit.io/dr5fryhth/Adobe%20Express%20-%20file.png?updatedAt=1762746280976" class="h-8 md:h-10" alt="Logo" />
                </a>
            </div>
            <div class="flex justify-end items-center col-span-1">
                <span id="user-name" class="text-primary-900 mr-4"></span>
                <a href="/api/logout" class="text-white bg-primary-900 hover:bg-jive-blue focus:ring-4 focus:ring-jive-teal/20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 ml-2 focus:outline-none">Sign Out</a>
            </div>
        </div>
    </nav>
</header>
        <div class="flex-grow py-12 px-4">
            <div class="max-w-6xl mx-auto">
                <h1 class="text-4xl font-extrabold text-primary-900 mb-8">My Dashboard</h1>
                
                <div id="event-info" class="bg-white rounded-lg shadow-lg p-6 mb-6">
                    <h2 class="text-2xl font-bold mb-4">Event Information</h2>
                    <div id="event-details"></div>
                </div>
                
                <div class="grid md:grid-cols-2 gap-6 mb-6">
                    <div class="bg-white rounded-lg shadow-lg p-6">
                        <h2 class="text-2xl font-bold mb-4">Purchase Tickets</h2>
                        <div id="purchase-section"></div>
                    </div>
                    
                    <div class="bg-white rounded-lg shadow-lg p-6">
                        <h2 class="text-2xl font-bold mb-4">My Tickets</h2>
                        <div id="tickets-list"></div>
                    </div>
                </div>
            </div>
        </div>
        <footer class="p-4 md:p-8 lg:p-10 relative">
  <div class="mx-auto max-w-screen-xl text-center">
      <div class="flex items-center justify-center">
        <h3>Event Ticketing System</h3>
      </div>
      <span class="text-sm text-gray-500 sm:text-center">&copy; 2025 <a href="#" class="hover:text-jive-teal transition">Event Tickets</a> by <a href="https://omaribrightswe.dpdns.org/" class="hover:text-jive-pink transition" target="_blank"><u>Bright Omari Owusu</u></a></span>
  </div>
</footer>    </div>
    <div id="alert_modal" tabindex="-1" aria-hidden="true" class="fixed top-0 left-0 right-0 z-50 hidden w-full p-4 overflow-x-hidden overflow-y-auto md:inset-0 h-[calc(100%-1rem)] md:h-full" role="dialog">
    <div class="relative w-full h-full max-w-lg md:h-auto">
        <div class="relative bg-white text-gray-900 rounded-lg shadow dark:bg-gray-700 dark:text-white">
            <div class="flex items-middle justify-between py-4 px-6 border-b rounded-t dark:border-gray-600">
                <h3 class="text-xl font-semibold alert-headline">Alert!</h3>
                <button type="button" class="text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-gray-600 dark:hover:text-white alert-button-close">
                    <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg>
                    <span class="sr-only">Close modal</span>
                </button>
            </div>
            <div class="p-6">
                <p class="text-base leading-relaxed alert-message">This is an alert...</p>
            </div>
            <div class="p-6 space-x-2 text-center">
                <button type="button" class="text-white bg-primary-700 hover:bg-primary-800 focus:ring-4 focus:outline-none focus:ring-primary-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 alert-button-confirm w-full">OK</button>
            </div>
        </div>
    </div>
</div>
<button data-modal-target="alert_modal" style="display:none;"></button>
<script type="text/javascript">
var AlertModal = (function(settings) {
    return {
        headline: settings.headline,
        message: settings.message,
        buttons: settings.buttons,
        _modal: null,
        open: function() {
            var modal = $('#alert_modal');
            if (this.headline != undefined) {
                $(modal).find('.alert-headline').html(this.headline);
            }
            if (this.message != undefined) {
                $(modal).find('.alert-message').html(this.message);
            }
            if (this.buttons != undefined) {
                if (this.buttons.confirm != undefined) {
                    $(modal).find('.alert-button-confirm').html(this.buttons.confirm);
                }
            }
            var scope = this;
            $(modal).find('.alert-button-confirm').unbind('click').click(function(e) {
                scope.confirm();
            });
            $(modal).find('.alert-button-close').unbind('click').click(function(e) {
                scope.close();
            });
            this._modal = new Modal(document.getElementById('alert_modal'));
            this._modal.show();
        },
        close: function() {
            this._modal.hide();
        },
        confirm: function() {
            if (settings.confirm != undefined) {
              settings.confirm();
            }
            this.close();
        }
    };
});
function loadDashboard() {
    $.get('/api/user', function(user) {
        if (user.success) {
            $('#user-name').text('Welcome, ' + user.data.first_name + '!');
        }
    });
    
    $.get('/api/event', function(event) {
        if (event.success && event.data) {
            var html = '<h3 class="text-xl font-bold mb-2">' + event.data.name + '</h3>';
            html += '<div class="grid md:grid-cols-2 gap-4 mt-4">';
            html += '<div><strong>VIP Tickets:</strong> $' + event.data.vip_price.toFixed(2) + ' (' + event.data.vip_available + ' available)</div>';
            html += '<div><strong>Regular Tickets:</strong> $' + event.data.regular_price.toFixed(2) + ' (' + event.data.regular_available + ' available)</div>';
            html += '</div>';
            $('#event-details').html(html);
            
            var purchaseHtml = '';
            if (event.data.vip_available > 0) {
                purchaseHtml += '<button onclick="purchaseTicket(\'VIP\')" class="w-full mb-2 text-white bg-primary-900 hover:bg-jive-green focus:ring-4 focus:outline-none focus:ring-jive-teal/30 font-semibold rounded-full px-6 py-3 transition">Buy VIP Ticket - $' + event.data.vip_price.toFixed(2) + '</button>';
            }
            if (event.data.regular_available > 0) {
                purchaseHtml += '<button onclick="purchaseTicket(\'REGULAR\')" class="w-full text-white bg-primary-900 hover:bg-jive-green focus:ring-4 focus:outline-none focus:ring-jive-teal/30 font-semibold rounded-full px-6 py-3 transition">Buy Regular Ticket - $' + event.data.regular_price.toFixed(2) + '</button>';
            }
            if (!purchaseHtml) {
                purchaseHtml = '<p class="text-gray-500">No tickets available</p>';
            }
            $('#purchase-section').html(purchaseHtml);
        } else {
            $('#event-details').html('<p class="text-gray-500">No event configured yet</p>');
            $('#purchase-section').html('<p class="text-gray-500">No event available</p>');
        }
    });
    
    $.get('/api/tickets', function(tickets) {
        if (tickets.success) {
            if (tickets.data.length > 0) {
                var html = '<div class="space-y-4">';
                tickets.data.forEach(function(ticket) {
                    html += '<div class="border rounded-lg p-4">';
                    html += '<div class="flex justify-between items-center">';
                    html += '<div><strong>' + ticket.ticket_type + '</strong> - $' + ticket.price.toFixed(2) + '</div>';
                    html += '<button onclick="cancelTicket(\'' + ticket.ticket_id + '\')" class="text-red-600 hover:text-red-800">Cancel</button>';
                    html += '</div>';
                    html += '<div class="text-sm text-gray-500 mt-2">ID: ' + ticket.ticket_id + '</div>';
                    html += '</div>';
                });
                html += '</div>';
                $('#tickets-list').html(html);
            } else {
                $('#tickets-list').html('<p class="text-gray-500">You don\\'t have any tickets yet</p>');
            }
        }
    });
}
function purchaseTicket(type) {
    $.ajax({
        url: '/api/purchase',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ticket_type: type }),
        success: function(response) {
            AlertModal({
                headline: response.success ? 'Success!' : 'Error',
                message: response.message,
                buttons: { confirm: 'OK' },
                confirm: function() {
                    if (response.success) {
                        loadDashboard();
                    }
                }
            }).open();
        }
    });
}
function cancelTicket(ticketId) {
    if (!confirm('Are you sure you want to cancel this ticket?')) return;
    $.ajax({
        url: '/api/cancel',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ticket_id: ticketId }),
        success: function(response) {
            AlertModal({
                headline: response.success ? 'Success!' : 'Error',
                message: response.message,
                buttons: { confirm: 'OK' },
                confirm: function() {
                    if (response.success) {
                        loadDashboard();
                    }
                }
            }).open();
        }
    });
}
$(document).ready(function() {
    loadDashboard();
});
</script>
</body>
</html>
"""


# Admin Dashboard HTML
ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard - Event Ticketing System</title>
  <link href="https://www.letsjive.io/includes/css/app.css?1762451922" rel="stylesheet" type="text/css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/flowbite/1.6.4/flowbite.min.js"></script>
</head>
<body class="relative">
    <div class="flex flex-col min-h-screen h-full mx-auto overflow-hidden relative">
        <header class="relative">
    <nav class="border-gray-200 px-4 lg:px-6 py-4 dark:bg-gray-800 relative z-50">
        <div class="grid grid-cols-3 items-center mx-auto max-w-screen-xl">
            <div class="flex justify-start items-center col-span-1">
                <a href="/" class="text-primary-900 bg-white border border-gray-200 hover:bg-jive-yellow focus:ring-4 focus:ring-jive-teal-20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 focus:outline-none">Home</a>
            </div>
            <div class="flex items-center justify-center">
                <a href="/" class="inline-block">
                    <img src="https://ik.imagekit.io/dr5fryhth/Adobe%20Express%20-%20file.png?updatedAt=1762746280976" class="h-8 md:h-10" alt="Logo" />
                </a>
            </div>
            <div class="flex justify-end items-center col-span-1">
                <span id="admin-name" class="text-primary-900 mr-4"></span>
                <a href="/api/logout" class="text-white bg-primary-900 hover:bg-jive-blue focus:ring-4 focus:ring-jive-teal/20 font-medium rounded-full text-sm md:text-base px-4 md:px-6 py-2 ml-2 focus:outline-none">Sign Out</a>
            </div>
        </div>
    </nav>
</header>
        <div class="flex-grow py-12 px-4">
            <div class="max-w-6xl mx-auto">
                <h1 class="text-4xl font-extrabold text-primary-900 mb-8">Admin Dashboard</h1>
                
                <div class="grid md:grid-cols-2 gap-6 mb-6">
                    <div class="bg-white rounded-lg shadow-lg p-6">
                        <h2 class="text-2xl font-bold mb-4">Create Event</h2>
                        <form id="create-event-form">
                            <div class="mb-4">
                                <label class="block text-sm font-medium text-gray-700 mb-2">Event Name</label>
                                <input type="text" id="event-name" required class="w-full px-4 py-3 border border-gray-300 rounded-lg">
                            </div>
                            <div class="mb-4">
                                <label class="block text-sm font-medium text-gray-700 mb-2">VIP Quantity</label>
                                <input type="number" id="vip-quantity" required class="w-full px-4 py-3 border border-gray-300 rounded-lg">
                            </div>
                            <div class="mb-4">
                                <label class="block text-sm font-medium text-gray-700 mb-2">VIP Price ($)</label>
                                <input type="number" step="0.01" id="vip-price" required class="w-full px-4 py-3 border border-gray-300 rounded-lg">
                            </div>
                            <div class="mb-4">
                                <label class="block text-sm font-medium text-gray-700 mb-2">Regular Quantity</label>
                                <input type="number" id="regular-quantity" required class="w-full px-4 py-3 border border-gray-300 rounded-lg">
                            </div>
                            <div class="mb-6">
                                <label class="block text-sm font-medium text-gray-700 mb-2">Regular Price ($)</label>
                                <input type="number" step="0.01" id="regular-price" required class="w-full px-4 py-3 border border-gray-300 rounded-lg">
                            </div>
                            <button type="submit" class="w-full text-white bg-primary-900 hover:bg-jive-green focus:ring-4 focus:outline-none focus:ring-jive-teal/30 font-semibold rounded-full px-6 py-3 transition">Create Event</button>
                        </form>
                    </div>
                    
                    <div class="bg-white rounded-lg shadow-lg p-6">
                        <h2 class="text-2xl font-bold mb-4">Sales Summary</h2>
                        <div id="sales-summary"></div>
                    </div>
                </div>
            </div>
        </div>
        <footer class="p-4 md:p-8 lg:p-10 relative">
  <div class="mx-auto max-w-screen-xl text-center">
      <div class="flex items-center justify-center">
        <h3>Event Ticketing System</h3>
      </div>
      <span class="text-sm text-gray-500 sm:text-center">&copy; 2025 <a href="#" class="hover:text-jive-teal transition">Event Tickets</a> by <a href="https://omaribrightswe.dpdns.org/" class="hover:text-jive-pink transition" target="_blank"><u>Bright Omari Owusu</u></a></span>
  </div>
</footer>    </div>
    <div id="alert_modal" tabindex="-1" aria-hidden="true" class="fixed top-0 left-0 right-0 z-50 hidden w-full p-4 overflow-x-hidden overflow-y-auto md:inset-0 h-[calc(100%-1rem)] md:h-full" role="dialog">
    <div class="relative w-full h-full max-w-lg md:h-auto">
        <div class="relative bg-white text-gray-900 rounded-lg shadow dark:bg-gray-700 dark:text-white">
            <div class="flex items-middle justify-between py-4 px-6 border-b rounded-t dark:border-gray-600">
                <h3 class="text-xl font-semibold alert-headline">Alert!</h3>
                <button type="button" class="text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-gray-600 dark:hover:text-white alert-button-close">
                    <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg>
                    <span class="sr-only">Close modal</span>
                </button>
            </div>
            <div class="p-6">
                <p class="text-base leading-relaxed alert-message">This is an alert...</p>
            </div>
            <div class="p-6 space-x-2 text-center">
                <button type="button" class="text-white bg-primary-700 hover:bg-primary-800 focus:ring-4 focus:outline-none focus:ring-primary-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-primary-600 dark:hover:bg-primary-700 dark:focus:ring-primary-800 alert-button-confirm w-full">OK</button>
            </div>
        </div>
    </div>
</div>
<button data-modal-target="alert_modal" style="display:none;"></button>
<script type="text/javascript">
var AlertModal = (function(settings) {
    return {
        headline: settings.headline,
        message: settings.message,
        buttons: settings.buttons,
        _modal: null,
        open: function() {
            var modal = $('#alert_modal');
            if (this.headline != undefined) {
                $(modal).find('.alert-headline').html(this.headline);
            }
            if (this.message != undefined) {
                $(modal).find('.alert-message').html(this.message);
            }
            if (this.buttons != undefined) {
                if (this.buttons.confirm != undefined) {
                    $(modal).find('.alert-button-confirm').html(this.buttons.confirm);
                }
            }
            var scope = this;
            $(modal).find('.alert-button-confirm').unbind('click').click(function(e) {
                scope.confirm();
            });
            $(modal).find('.alert-button-close').unbind('click').click(function(e) {
                scope.close();
            });
            this._modal = new Modal(document.getElementById('alert_modal'));
            this._modal.show();
        },
        close: function() {
            this._modal.hide();
        },
        confirm: function() {
            if (settings.confirm != undefined) {
              settings.confirm();
            }
            this.close();
        }
    };
});
function loadSalesSummary() {
    $.get('/api/sales', function(response) {
        if (response.success && response.data) {
            var s = response.data;
            var html = '<div class="space-y-4">';
            html += '<div><strong>Event:</strong> ' + s.event_name + '</div>';
            html += '<div><strong>VIP Tickets:</strong> ' + s.vip_sold + ' / ' + s.vip_total + ' sold ($' + s.vip_revenue.toFixed(2) + ')</div>';
            html += '<div><strong>Regular Tickets:</strong> ' + s.regular_sold + ' / ' + s.regular_total + ' sold ($' + s.regular_revenue.toFixed(2) + ')</div>';
            html += '<div class="pt-4 border-t"><strong>Total Revenue:</strong> $' + s.total_revenue.toFixed(2) + '</div>';
            html += '</div>';
            $('#sales-summary').html(html);
        } else {
            $('#sales-summary').html('<p class="text-gray-500">No event data available</p>');
        }
    });
}
$(document).ready(function() {
    $.get('/api/user', function(user) {
        if (user.success) {
            $('#admin-name').text('Admin: ' + user.data.first_name);
        }
    });
    
    loadSalesSummary();
    
    $('#create-event-form').submit(function(e) {
        e.preventDefault();
        $.ajax({
            url: '/api/create-event',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                name: $('#event-name').val(),
                vip_quantity: parseInt($('#vip-quantity').val()),
                vip_price: parseFloat($('#vip-price').val()),
                regular_quantity: parseInt($('#regular-quantity').val()),
                regular_price: parseFloat($('#regular-price').val())
            }),
            success: function(response) {
                AlertModal({
                    headline: response.success ? 'Success!' : 'Error',
                    message: response.message,
                    buttons: { confirm: 'OK' },
                    confirm: function() {
                        if (response.success) {
                            $('#create-event-form')[0].reset();
                            loadSalesSummary();
                        }
                    }
                }).open();
            }
        });
    });
});
</script>
</body>
</html>
"""


# ============================================================================
# FLASK ROUTES
# ============================================================================

@app.route('/')
def index():
    """Landing page."""
    return render_template_string(INDEX_HTML)


@app.route('/signin')
def signin():
    """Sign-in page."""
    return render_template_string(SIGNIN_HTML)


@app.route('/signup')
def signup():
    """Sign-up page."""
    return render_template_string(SIGNUP_HTML)


@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard."""
    user = get_current_user()
    if user and user.is_admin:
        return redirect(url_for('admin'))
    return render_template_string(DASHBOARD_HTML)


@app.route('/admin')
@admin_required
def admin():
    """Admin dashboard."""
    return render_template_string(ADMIN_HTML)


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/register', methods=['POST'])
def api_register():
    """Handle user registration."""
    data = request.get_json()
    success, message, user = auth_service.register_user(
        data.get('first_name', ''),
        data.get('last_name', ''),
        data.get('email', ''),
        data.get('phone', ''),
        data.get('password', ''),
        data.get('password_confirm', '')
    )
    
    if success:
        TransactionService.log_transaction(
            user.user_id,
            user.email,
            "N/A",
            "register",
            "success",
            0.0,
            f"User registered: {user.email}"
        )
    
    return jsonify({
        'success': success,
        'message': message
    })


@app.route('/api/login', methods=['POST'])
def api_login():
    """Handle user login."""
    data = request.get_json()
    success, message, user = auth_service.login(
        data.get('identifier', ''),
        data.get('password', '')
    )
    
    if success:
        session['user_id'] = user.user_id
        TransactionService.log_transaction(
            user.user_id,
            user.email,
            "N/A",
            "login",
            "success",
            0.0,
            f"User logged in: {user.email}"
        )
        redirect_url = '/admin' if user.is_admin else '/dashboard'
        return jsonify({
            'success': True,
            'message': message,
            'redirect': redirect_url
        })
    
    return jsonify({
        'success': False,
        'message': message
    })


@app.route('/api/logout', methods=['POST', 'GET'])
def api_logout():
    """Handle user logout."""
    session.clear()
    return redirect(url_for('index'))


@app.route('/api/user', methods=['GET'])
@login_required
def api_user():
    """Get current user info."""
    user = get_current_user()
    if user:
        return jsonify({
            'success': True,
            'data': {
                'user_id': user.user_id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'is_admin': user.is_admin
            }
        })
    return jsonify({'success': False, 'message': 'User not found'})


@app.route('/api/event', methods=['GET'])
def api_event():
    """Get event information."""
    event = ticket_service.get_event()
    if event:
        return jsonify({
            'success': True,
            'data': {
                'name': event.name,
                'vip_price': event.vip_price,
                'vip_available': event.get_vip_available(),
                'regular_price': event.regular_price,
                'regular_available': event.get_regular_available()
            }
        })
    return jsonify({'success': False, 'message': 'No event configured'})


@app.route('/api/create-event', methods=['POST'])
@admin_required
def api_create_event():
    """Create a new event (admin only)."""
    data = request.get_json()
    success, message = ticket_service.create_event(
        data.get('name', ''),
        int(data.get('vip_quantity', 0)),
        float(data.get('vip_price', 0)),
        int(data.get('regular_quantity', 0)),
        float(data.get('regular_price', 0))
    )
    
    if success:
        user = get_current_user()
        TransactionService.log_transaction(
            user.user_id,
            user.email,
            "N/A",
            "create_event",
            "success",
            0.0,
            f"Created event: {data.get('name', '')}"
        )
    
    return jsonify({
        'success': success,
        'message': message
    })


@app.route('/api/tickets', methods=['GET'])
@login_required
def api_tickets():
    """Get user's tickets."""
    user = get_current_user()
    tickets = ticket_service.get_user_tickets(user)
    return jsonify({
        'success': True,
        'data': [ticket.to_dict() for ticket in tickets]
    })


@app.route('/api/purchase', methods=['POST'])
@login_required
def api_purchase():
    """Handle ticket purchase."""
    user = get_current_user()
    data = request.get_json()
    ticket_type = data.get('ticket_type', '').upper()
    
    success, message, ticket = ticket_service.purchase_ticket(user, ticket_type)
    
    price = 0.0
    if ticket:
        price = ticket.price
    
    TransactionService.log_transaction(
        user.user_id,
        user.email,
        ticket_type,
        "purchase",
        "success" if success else "failed",
        price,
        message
    )
    
    return jsonify({
        'success': success,
        'message': message
    })


@app.route('/api/cancel', methods=['POST'])
@login_required
def api_cancel():
    """Handle ticket cancellation."""
    user = get_current_user()
    data = request.get_json()
    ticket_id = data.get('ticket_id', '')
    
    # Get ticket info before cancellation
    tickets = ticket_service.get_user_tickets(user)
    ticket_info = None
    for t in tickets:
        if t.ticket_id == ticket_id:
            ticket_info = t
            break
    
    success, message = ticket_service.cancel_ticket(ticket_id, user)
    
    price = ticket_info.price if ticket_info else 0.0
    ticket_type = ticket_info.ticket_type if ticket_info else "N/A"
    
    TransactionService.log_transaction(
        user.user_id,
        user.email,
        ticket_type,
        "cancel",
        "success" if success else "failed",
        price,
        message
    )
    
    return jsonify({
        'success': success,
        'message': message
    })


@app.route('/api/sales', methods=['GET'])
@admin_required
def api_sales():
    """Get sales summary (admin only)."""
    summary = ticket_service.get_sales_summary()
    if summary:
        return jsonify({
            'success': True,
            'data': summary
        })
    return jsonify({
        'success': False,
        'message': 'No event data available'
    })


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    StorageManager.initialize_storage()
    print("=" * 60)
    print("Event Ticketing System - Web Server")
    print("=" * 60)
    print("Server starting on http://127.0.0.1:5000")
    print("Open this URL in your browser")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5000, debug=False)

