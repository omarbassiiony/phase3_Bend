package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os" // <-- needed for os.Getenv
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// User struct
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Event struct
type Event struct {
	ID            int    `json:"id"`
	Title         string `json:"title"`
	Date          string `json:"date"`
	Time          string `json:"time"`
	Location      string `json:"location"`
	Description   string `json:"description"`
	OrganizerID   int    `json:"organizerId"`
	OrganizerName string `json:"organizerName,omitempty"`
	CreatedAt     string `json:"createdAt,omitempty"`
}

// EventParticipant struct
type EventParticipant struct {
	ID        int    `json:"id"`
	EventID   int    `json:"eventId"`
	UserID    int    `json:"userId"`
	Username  string `json:"username,omitempty"`
	Email     string `json:"email,omitempty"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	InvitedAt string `json:"invitedAt,omitempty"`
}

// EventWithRole struct
type EventWithRole struct {
	Event
	UserRole         string `json:"userRole"`
	ParticipantCount int    `json:"participantCount,omitempty"`
	UserStatus       string `json:"userStatus,omitempty"`
}

// Response struct
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var db *sql.DB

// Initialize database
func initDB() {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}

	// Wait for database to be ready
	for {
		err = db.Ping()
		if err == nil {
			break
		}
		fmt.Println("Waiting for database...")
		time.Sleep(2 * time.Second)
	}

	fmt.Println("Successfully connected to database!")
}

// Hash password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Check password hash
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Enable CORS
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Get user ID from Authorization header
func getUserIDFromHeader(r *http.Request) (int, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return 0, fmt.Errorf("authorization header missing")
	}

	// Extract user ID from "Bearer <userID>"
	var userID int
	_, err := fmt.Sscanf(authHeader, "Bearer %d", &userID)
	if err != nil {
		return 0, fmt.Errorf("invalid authorization header")
	}

	return userID, nil
}

// ==================== AUTH HANDLERS ====================

func signup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	if user.Username == "" || user.Email == "" || user.Password == "" {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "All fields are required",
		})
		return
	}

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error hashing password",
		})
		return
	}

	query := "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"
	result, err := db.Exec(query, user.Username, user.Email, hashedPassword)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Username or email already exists",
		})
		return
	}

	id, _ := result.LastInsertId()
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "User registered successfully",
		Data: map[string]interface{}{
			"id":       id,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var credentials User
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	if credentials.Email == "" || credentials.Password == "" {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Email and password are required",
		})
		return
	}

	var user User
	query := "SELECT id, username, email, password FROM users WHERE email = ?"
	err = db.QueryRow(query, credentials.Email).Scan(&user.ID, &user.Username, &user.Email, &user.Password)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	if !checkPasswordHash(credentials.Password, user.Password) {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Login successful",
		Data: map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}

// ==================== EVENT HANDLERS ====================

// Create Event
func createEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromHeader(r)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	var event Event
	err = json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	// Validate required fields
	if event.Title == "" || event.Date == "" || event.Time == "" || event.Location == "" || event.Description == "" {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "All fields are required",
		})
		return
	}

	// Insert event
	query := "INSERT INTO events (title, date, time, location, description, organizer_id) VALUES (?, ?, ?, ?, ?, ?)"
	result, err := db.Exec(query, event.Title, event.Date, event.Time, event.Location, event.Description, userID)
	if err != nil {
		log.Println("Error creating event:", err)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error creating event",
		})
		return
	}

	eventID, _ := result.LastInsertId()

	// Add organizer as participant
	participantQuery := "INSERT INTO event_participants (event_id, user_id, role, status) VALUES (?, ?, 'organizer', 'going')"
	_, err = db.Exec(participantQuery, eventID, userID)
	if err != nil {
		log.Println("Error adding organizer:", err)
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Event created successfully",
		Data: map[string]interface{}{
			"id": eventID,
		},
	})
}

// Get all events (organized + invited)
func getAllMyEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromHeader(r)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	// Get organized events
	organizedQuery := `
		SELECT e.id, e.title, e.date, e.time, e.location, e.description, e.organizer_id, u.username, e.created_at
		FROM events e
		JOIN users u ON e.organizer_id = u.id
		WHERE e.organizer_id = ?
		ORDER BY e.date DESC, e.time DESC
	`
	organizedRows, err := db.Query(organizedQuery, userID)
	if err != nil {
		log.Println("Error fetching organized events:", err)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error fetching events",
		})
		return
	}
	defer organizedRows.Close()

	var organizedEvents []EventWithRole
	for organizedRows.Next() {
		var event EventWithRole
		organizedRows.Scan(&event.ID, &event.Title, &event.Date, &event.Time, &event.Location,
			&event.Description, &event.OrganizerID, &event.OrganizerName, &event.CreatedAt)
		event.UserRole = "organizer"
		organizedEvents = append(organizedEvents, event)
	}

	// Get invited events
	invitedQuery := `
		SELECT e.id, e.title, e.date, e.time, e.location, e.description, e.organizer_id, u.username, e.created_at, ep.status
		FROM events e
		JOIN users u ON e.organizer_id = u.id
		JOIN event_participants ep ON e.id = ep.event_id
		WHERE ep.user_id = ? AND ep.role = 'attendee'
		ORDER BY e.date DESC, e.time DESC
	`
	invitedRows, err := db.Query(invitedQuery, userID)
	if err != nil {
		log.Println("Error fetching invited events:", err)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error fetching events",
		})
		return
	}
	defer invitedRows.Close()

	var invitedEvents []EventWithRole
	for invitedRows.Next() {
		var event EventWithRole
		invitedRows.Scan(&event.ID, &event.Title, &event.Date, &event.Time, &event.Location,
			&event.Description, &event.OrganizerID, &event.OrganizerName, &event.CreatedAt, &event.UserStatus)
		event.UserRole = "attendee"
		invitedEvents = append(invitedEvents, event)
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Events fetched successfully",
		Data: map[string]interface{}{
			"organized": organizedEvents,
			"invited":   invitedEvents,
		},
	})
}

// Get organized events only
func getMyOrganizedEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromHeader(r)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	query := `
		SELECT e.id, e.title, e.date, e.time, e.location, e.description, e.organizer_id, u.username, e.created_at,
		(SELECT COUNT(*) FROM event_participants WHERE event_id = e.id) as participant_count
		FROM events e
		JOIN users u ON e.organizer_id = u.id
		WHERE e.organizer_id = ?
		ORDER BY e.date DESC, e.time DESC
	`
	rows, err := db.Query(query, userID)
	if err != nil {
		log.Println("Error fetching events:", err)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error fetching events",
		})
		return
	}
	defer rows.Close()

	var events []EventWithRole
	for rows.Next() {
		var event EventWithRole
		rows.Scan(&event.ID, &event.Title, &event.Date, &event.Time, &event.Location,
			&event.Description, &event.OrganizerID, &event.OrganizerName, &event.CreatedAt, &event.ParticipantCount)
		event.UserRole = "organizer"
		events = append(events, event)
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Events fetched successfully",
		Data:    events,
	})
}

// Get invited events only
func getMyInvitedEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromHeader(r)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	query := `
		SELECT e.id, e.title, e.date, e.time, e.location, e.description, e.organizer_id, u.username, e.created_at, ep.status
		FROM events e
		JOIN users u ON e.organizer_id = u.id
		JOIN event_participants ep ON e.id = ep.event_id
		WHERE ep.user_id = ? AND ep.role = 'attendee'
		ORDER BY e.date DESC, e.time DESC
	`
	rows, err := db.Query(query, userID)
	if err != nil {
		log.Println("Error fetching events:", err)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error fetching events",
		})
		return
	}
	defer rows.Close()

	var events []EventWithRole
	for rows.Next() {
		var event EventWithRole
		rows.Scan(&event.ID, &event.Title, &event.Date, &event.Time, &event.Location,
			&event.Description, &event.OrganizerID, &event.OrganizerName, &event.CreatedAt, &event.UserStatus)
		event.UserRole = "attendee"
		events = append(events, event)
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Events fetched successfully",
		Data:    events,
	})
}

// Get event by ID
func getEventByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromHeader(r)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	vars := mux.Vars(r)
	eventID, err := strconv.Atoi(vars["id"])
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid event ID",
		})
		return
	}

	query := `
		SELECT e.id, e.title, e.date, e.time, e.location, e.description, e.organizer_id, u.username, e.created_at
		FROM events e
		JOIN users u ON e.organizer_id = u.id
		WHERE e.id = ?
	`
	var event EventWithRole
	err = db.QueryRow(query, eventID).Scan(&event.ID, &event.Title, &event.Date, &event.Time,
		&event.Location, &event.Description, &event.OrganizerID, &event.OrganizerName, &event.CreatedAt)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Event not found",
		})
		return
	}

	// Check user's role
	var role string
	var status string
	roleQuery := "SELECT role, status FROM event_participants WHERE event_id = ? AND user_id = ?"
	err = db.QueryRow(roleQuery, eventID, userID).Scan(&role, &status)
	if err == nil {
		event.UserRole = role
		event.UserStatus = status
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Event fetched successfully",
		Data:    event,
	})
}

// Get event participants
func getEventParticipants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromHeader(r)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	vars := mux.Vars(r)
	eventID, err := strconv.Atoi(vars["id"])
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid event ID",
		})
		return
	}

	// Check if user is organizer
	var organizerID int
	err = db.QueryRow("SELECT organizer_id FROM events WHERE id = ?", eventID).Scan(&organizerID)
	if err != nil || organizerID != userID {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Access denied",
		})
		return
	}

	query := `
		SELECT ep.id, ep.event_id, ep.user_id, u.username, u.email, ep.role, ep.status, ep.invited_at
		FROM event_participants ep
		JOIN users u ON ep.user_id = u.id
		WHERE ep.event_id = ?
		ORDER BY ep.role DESC, u.username ASC
	`
	rows, err := db.Query(query, eventID)
	if err != nil {
		log.Println("Error fetching participants:", err)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error fetching participants",
		})
		return
	}
	defer rows.Close()

	var participants []EventParticipant
	for rows.Next() {
		var p EventParticipant
		rows.Scan(&p.ID, &p.EventID, &p.UserID, &p.Username, &p.Email, &p.Role, &p.Status, &p.InvitedAt)
		participants = append(participants, p)
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Participants fetched successfully",
		Data:    participants,
	})
}

// Invite user to event
func inviteUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromHeader(r)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	vars := mux.Vars(r)
	eventID, err := strconv.Atoi(vars["id"])
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid event ID",
		})
		return
	}

	// Check if user is organizer
	var organizerID int
	err = db.QueryRow("SELECT organizer_id FROM events WHERE id = ?", eventID).Scan(&organizerID)
	if err != nil || organizerID != userID {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Only organizers can invite users",
		})
		return
	}

	var requestData struct {
		Email string `json:"email"`
	}
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil || requestData.Email == "" {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Email is required",
		})
		return
	}

	// Get user ID by email
	var invitedUserID int
	err = db.QueryRow("SELECT id FROM users WHERE email = ?", requestData.Email).Scan(&invitedUserID)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "User not found",
		})
		return
	}

	// Check if already invited
	var existingID int
	err = db.QueryRow("SELECT id FROM event_participants WHERE event_id = ? AND user_id = ?", eventID, invitedUserID).Scan(&existingID)
	if err == nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "User already invited",
		})
		return
	}

	// Add participant
	query := "INSERT INTO event_participants (event_id, user_id, role, status) VALUES (?, ?, 'attendee', 'maybe')"
	_, err = db.Exec(query, eventID, invitedUserID)
	if err != nil {
		log.Println("Error inviting user:", err)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error inviting user",
		})
		return
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "User invited successfully",
	})
}

// Update attendee status
func updateAttendeeStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromHeader(r)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	vars := mux.Vars(r)
	eventID, err := strconv.Atoi(vars["id"])
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid event ID",
		})
		return
	}

	var requestData struct {
		Status string `json:"status"`
	}
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil || (requestData.Status != "going" && requestData.Status != "maybe" && requestData.Status != "not going") {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid status. Must be 'going', 'maybe', or 'not going'",
		})
		return
	}

	// Update status
	query := "UPDATE event_participants SET status = ? WHERE event_id = ? AND user_id = ?"
	result, err := db.Exec(query, requestData.Status, eventID, userID)
	if err != nil {
		log.Println("Error updating status:", err)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error updating status",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "You are not invited to this event",
		})
		return
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Status updated successfully",
	})
}

// Delete event
func deleteEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, err := getUserIDFromHeader(r)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	vars := mux.Vars(r)
	eventID, err := strconv.Atoi(vars["id"])
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid event ID",
		})
		return
	}

	// Check if user is organizer
	var organizerID int
	err = db.QueryRow("SELECT organizer_id FROM events WHERE id = ?", eventID).Scan(&organizerID)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Event not found",
		})
		return
	}

	if organizerID != userID {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Only organizers can delete events",
		})
		return
	}

	// Delete event (participants will be deleted automatically due to CASCADE)
	query := "DELETE FROM events WHERE id = ?"
	_, err = db.Exec(query, eventID)
	if err != nil {
		log.Println("Error deleting event:", err)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error deleting event",
		})
		return
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Event deleted successfully",
	})
}

// Main function
func main() {
	initDB()
	defer db.Close()

	router := mux.NewRouter()

	// Auth routes
	router.HandleFunc("/api/signup", signup).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/login", login).Methods("POST", "OPTIONS")

	// Event routes
	router.HandleFunc("/api/events", createEvent).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/events/my-events", getAllMyEvents).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/events/organized", getMyOrganizedEvents).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/events/invited", getMyInvitedEvents).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/events/{id}", getEventByID).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/events/{id}", deleteEvent).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/api/events/{id}/participants", getEventParticipants).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/events/{id}/invite", inviteUser).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/events/{id}/status", updateAttendeeStatus).Methods("PUT", "OPTIONS")

	handler := enableCORS(router)

	port := ":8080"
	fmt.Printf("Server is running on http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, handler))
}
