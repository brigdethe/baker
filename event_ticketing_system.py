import json
import csv
import os
import re
import hashlib
import uuid
from datetime import datetime
from collections import deque
from typing import Optional, Dict, List, Tuple, Any
from getpass import getpass

# Constants
DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
EVENT_FILE = os.path.join(DATA_DIR, "event.json")
TICKETS_FILE = os.path.join(DATA_DIR, "tickets.json")
TRANSACTIONS_FILE = "transactions.csv"
ADMIN_EMAIL = "admin@eventtickets.com"
ADMIN_DEFAULT_PASSWORD = "admin123"


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
# SECTION 4: DATA MODELS
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


class CLIInterface:
    """Text-based user interface for the ticketing system."""
    
    def __init__(self):
        self.auth_service = AuthService()
        self.ticket_service = TicketService()
        self.current_user = None
    
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self, title: str):
        """Print a formatted header."""
        print("\n" + "=" * 60)
        print(f" {title.center(58)} ")
        print("=" * 60 + "\n")
    
    def print_line(self):
        """Print a separator line."""
        print("-" * 60)
    
    def pause(self):
        """Pause and wait for user input."""
        input("\nPress Enter to continue...")
    
    def run(self):
        """Main application loop."""
        StorageManager.initialize_storage()
        
        self.print_header("EVENT TICKETING SYSTEM")
        print("Welcome! Please login or register to continue.\n")
        
        while True:
            if not self.current_user:
                self.main_menu()
            else:
                if self.current_user.is_admin:
                    self.admin_menu()
                else:
                    self.user_menu()
    
    def main_menu(self):
        """Display main menu for non-authenticated users."""
        self.print_line()
        print("MAIN MENU")
        self.print_line()
        print("1. Login")
        print("2. Register")
        print("3. Exit")
        self.print_line()
        
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == "1":
            self.login_screen()
        elif choice == "2":
            self.register_screen()
        elif choice == "3":
            print("\nThank you for using Event Ticketing System!")
            exit(0)
        else:
            print("Invalid choice. Please try again.")
            self.pause()
    
    def login_screen(self):
        """Display login screen."""
        self.clear_screen()
        self.print_header("LOGIN")
        
        identifier = input("Enter email or phone number: ").strip()
        password = getpass("Enter password: ")
        
        success, message, user = self.auth_service.login(identifier, password)
        
        if success:
            self.current_user = user
            print(f"\n✓ {message}")
            print(f"Welcome back, {user.get_full_name()}!")
            self.pause()
        else:
            print(f"\n✗ {message}")
            self.pause()
    
    def register_screen(self):
        """Display registration screen."""
        self.clear_screen()
        self.print_header("USER REGISTRATION")
        
        print("Please enter your information:\n")
        
        first_name = input("First Name: ").strip()
        last_name = input("Last Name: ").strip()
        email = input("Email: ").strip()
        phone = input("Phone Number: ").strip()
        password = getpass("Password (min 6 characters): ")
        password_confirm = getpass("Confirm Password: ")
        
        success, message, user = self.auth_service.register_user(
            first_name, last_name, email, phone, password, password_confirm
        )
        
        if success:
            print(f"\n✓ {message}")
            print("You can now login with your credentials.")
        else:
            print(f"\n✗ {message}")
        
        self.pause()
    
    def admin_menu(self):
        """Display admin menu."""
        self.clear_screen()
        self.print_header("ADMIN DASHBOARD")
        
        event = self.ticket_service.get_event()
        
        if not event:
            print("⚠ No event configured yet!\n")
            print("1. Create Event")
            print("2. Logout")
            self.print_line()
            
            choice = input("Enter your choice (1-2): ").strip()
            
            if choice == "1":
                self.create_event_screen()
            elif choice == "2":
                self.logout()
            else:
                print("Invalid choice.")
                self.pause()
        else:
            print(f"Event: {event.name}\n")
            print("1. View Sales Summary")
            print("2. View All Transactions")
            print("3. View Ticket Availability")
            print("4. Create New Event (Replace Current)")
            print("5. Logout")
            self.print_line()
            
            choice = input("Enter your choice (1-5): ").strip()
            
            if choice == "1":
                self.view_sales_summary()
            elif choice == "2":
                self.view_transactions()
            elif choice == "3":
                self.view_availability()
            elif choice == "4":
                self.create_event_screen()
            elif choice == "5":
                self.logout()
            else:
                print("Invalid choice.")
                self.pause()
    
    def create_event_screen(self):
        """Display event creation screen."""
        self.clear_screen()
        self.print_header("CREATE EVENT")
        
        try:
            name = input("Event Name: ").strip()
            if not name:
                print("Event name cannot be empty.")
                self.pause()
                return
            
            vip_quantity = int(input("VIP Ticket Quantity: "))
            vip_price = float(input("VIP Ticket Price ($): "))
            regular_quantity = int(input("Regular Ticket Quantity: "))
            regular_price = float(input("Regular Ticket Price ($): "))
            
            success, message = self.ticket_service.create_event(
                name, vip_quantity, vip_price, regular_quantity, regular_price
            )
            
            if success:
                print(f"\n✓ {message}")
                TransactionService.log_transaction(
                    self.current_user.user_id,
                    self.current_user.email,
                    "N/A",
                    "create_event",
                    "success",
                    0.0,
                    f"Created event: {name}"
                )
            else:
                print(f"\n✗ {message}")
        
        except ValueError:
            print("\n✗ Invalid input. Please enter numbers for quantities and prices.")
        
        self.pause()
    
    def view_sales_summary(self):
        """Display sales summary."""
        self.clear_screen()
        self.print_header("SALES SUMMARY")
        
        summary = self.ticket_service.get_sales_summary()
        
        if not summary:
            print("No event data available.")
        else:
            print(f"Event: {summary['event_name']}\n")
            
            print("VIP TICKETS:")
            print(f"  Sold: {summary['vip_sold']} / {summary['vip_total']}")
            print(f"  Available: {summary['vip_available']}")
            print(f"  Revenue: ${summary['vip_revenue']:.2f}\n")
            
            print("REGULAR TICKETS:")
            print(f"  Sold: {summary['regular_sold']} / {summary['regular_total']}")
            print(f"  Available: {summary['regular_available']}")
            print(f"  Revenue: ${summary['regular_revenue']:.2f}\n")
            
            self.print_line()
            print(f"TOTAL TICKETS SOLD: {summary['total_tickets_sold']}")
            print(f"TOTAL REVENUE: ${summary['total_revenue']:.2f}")
        
        self.pause()
    
    def view_transactions(self):
        """Display all transactions."""
        self.clear_screen()
        self.print_header("TRANSACTION LOG")
        
        try:
            with open(TRANSACTIONS_FILE, 'r') as f:
                reader = csv.reader(f)
                rows = list(reader)
                
                if len(rows) <= 1:
                    print("No transactions yet.")
                else:
                    header = rows[0]
                    print(" | ".join(header))
                    self.print_line()
                    
                    for row in rows[-20:]:
                        print(" | ".join(row))
        except FileNotFoundError:
            print("No transactions yet.")
        
        self.pause()
    
    def view_availability(self):
        """Display ticket availability."""
        self.clear_screen()
        self.print_header("TICKET AVAILABILITY")
        
        event = self.ticket_service.get_event()
        
        if not event:
            print("No event configured.")
        else:
            print(f"Event: {event.name}\n")
            print(f"VIP Tickets:")
            print(f"  Price: ${event.vip_price:.2f}")
            print(f"  Available: {event.get_vip_available()} / {event.vip_quantity}\n")
            
            print(f"Regular Tickets:")
            print(f"  Price: ${event.regular_price:.2f}")
            print(f"  Available: {event.get_regular_available()} / {event.regular_quantity}")
        
        self.pause()
    
    def user_menu(self):
        """Display user menu."""
        self.clear_screen()
        self.print_header("USER MENU")
        
        print(f"Welcome, {self.current_user.get_full_name()}!\n")
        
        print("1. View Available Tickets")
        print("2. Purchase Ticket")
        print("3. View My Tickets")
        print("4. Cancel Ticket")
        print("5. Logout")
        self.print_line()
        
        choice = input("Enter your choice (1-5): ").strip()
        
        if choice == "1":
            self.view_availability()
        elif choice == "2":
            self.purchase_ticket_screen()
        elif choice == "3":
            self.view_my_tickets()
        elif choice == "4":
            self.cancel_ticket_screen()
        elif choice == "5":
            self.logout()
        else:
            print("Invalid choice.")
            self.pause()
    
    def purchase_ticket_screen(self):
        """Display ticket purchase screen."""
        self.clear_screen()
        self.print_header("PURCHASE TICKET")
        
        event = self.ticket_service.get_event()
        
        if not event:
            print("No event available for booking.")
            self.pause()
            return
        
        print(f"Event: {event.name}\n")
        print("Available Tickets:")
        print(f"1. VIP - ${event.vip_price:.2f} ({event.get_vip_available()} available)")
        print(f"2. Regular - ${event.regular_price:.2f} ({event.get_regular_available()} available)")
        print("3. Cancel")
        self.print_line()
        
        choice = input("Select ticket type (1-3): ").strip()
        
        if choice == "1":
            ticket_type = "VIP"
        elif choice == "2":
            ticket_type = "REGULAR"
        elif choice == "3":
            return
        else:
            print("Invalid choice.")
            self.pause()
            return
        
        price = event.vip_price if ticket_type == "VIP" else event.regular_price
        confirm = input(f"\nConfirm purchase of {ticket_type} ticket for ${price:.2f}? (yes/no): ").strip().lower()
        
        if confirm != "yes":
            print("Purchase cancelled.")
            self.pause()
            return
        
        success, message, ticket = self.ticket_service.purchase_ticket(self.current_user, ticket_type)
        
        if success:
            print(f"\n✓ {message}")
            print(f"Ticket ID: {ticket.ticket_id}")
            TransactionService.log_transaction(
                self.current_user.user_id,
                self.current_user.email,
                ticket_type,
                "purchase",
                "success",
                price,
                message
            )
        else:
            print(f"\n✗ {message}")
            TransactionService.log_transaction(
                self.current_user.user_id,
                self.current_user.email,
                ticket_type,
                "purchase",
                "failed",
                price,
                message
            )
        
        self.pause()
    
    def view_my_tickets(self):
        """Display user's tickets."""
        self.clear_screen()
        self.print_header("MY TICKETS")
        
        tickets = self.ticket_service.get_user_tickets(self.current_user)
        
        if not tickets:
            print("You don't have any active tickets.")
        else:
            event = self.ticket_service.get_event()
            print(f"Event: {event.name}\n")
            
            for i, ticket in enumerate(tickets, 1):
                print(f"{i}. Ticket ID: {ticket.ticket_id}")
                print(f"   Type: {ticket.ticket_type}")
                print(f"   Price: ${ticket.price:.2f}")
                print(f"   Purchased: {ticket.purchased_at}")
                print()
        
        self.pause()
    
    def cancel_ticket_screen(self):
        """Display ticket cancellation screen."""
        self.clear_screen()
        self.print_header("CANCEL TICKET")
        
        tickets = self.ticket_service.get_user_tickets(self.current_user)
        
        if not tickets:
            print("You don't have any active tickets to cancel.")
            self.pause()
            return
        
        print("Your Active Tickets:\n")
        for i, ticket in enumerate(tickets, 1):
            print(f"{i}. {ticket.ticket_type} Ticket - ${ticket.price:.2f}")
            print(f"   ID: {ticket.ticket_id}")
            print()
        
        print(f"{len(tickets) + 1}. Cancel")
        self.print_line()
        
        try:
            choice = int(input(f"Select ticket to cancel (1-{len(tickets) + 1}): ").strip())
            
            if choice == len(tickets) + 1:
                return
            
            if 1 <= choice <= len(tickets):
                selected_ticket = tickets[choice - 1]
                
                confirm = input(f"\nConfirm cancellation of {selected_ticket.ticket_type} ticket? (yes/no): ").strip().lower()
                
                if confirm != "yes":
                    print("Cancellation aborted.")
                    self.pause()
                    return
                
                success, message = self.ticket_service.cancel_ticket(selected_ticket.ticket_id, self.current_user)
                
                if success:
                    print(f"\n✓ {message}")
                    TransactionService.log_transaction(
                        self.current_user.user_id,
                        self.current_user.email,
                        selected_ticket.ticket_type,
                        "cancel",
                        "success",
                        selected_ticket.price,
                        message
                    )
                else:
                    print(f"\n✗ {message}")
                    TransactionService.log_transaction(
                        self.current_user.user_id,
                        self.current_user.email,
                        selected_ticket.ticket_type,
                        "cancel",
                        "failed",
                        selected_ticket.price,
                        message
                    )
            else:
                print("Invalid choice.")
        
        except ValueError:
            print("Invalid input.")
        
        self.pause()
    
    def logout(self):
        """Logout current user."""
        print(f"\nGoodbye, {self.current_user.get_full_name()}!")
        self.current_user = None
        self.pause()


def main():
    """Main entry point of the application."""
    try:
        app = CLIInterface()
        app.run()
    except KeyboardInterrupt:
        print("\n\nApplication terminated by user.")
        exit(0)
    except Exception as e:
        print(f"\n\nAn unexpected error occurred: {e}")
        print("Please report this issue.")
        exit(1)


if __name__ == "__main__":
    main()

