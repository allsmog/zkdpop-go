package storage

import (
	"fmt"
	"testing"
	"time"
)

func TestMemoryStore_UserOperations(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	pk := "test-public-key"

	t.Run("CreateUser", func(t *testing.T) {
		err := store.CreateUser(pk)
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		// Creating same user again should fail
		err = store.CreateUser(pk)
		if err != ErrUserExists {
			t.Errorf("expected ErrUserExists, got %v", err)
		}
	})

	t.Run("GetUser", func(t *testing.T) {
		user, err := store.GetUser(pk)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}

		if user.PK != pk {
			t.Errorf("wrong public key: %s", user.PK)
		}

		if user.Status != "active" {
			t.Errorf("wrong status: %s", user.Status)
		}

		if time.Since(user.CreatedAt) > time.Second {
			t.Error("created_at should be recent")
		}
	})

	t.Run("GetNonexistentUser", func(t *testing.T) {
		_, err := store.GetUser("nonexistent-pk")
		if err != ErrUserNotFound {
			t.Errorf("expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("UpdateUserStatus", func(t *testing.T) {
		err := store.UpdateUserStatus(pk, "banned")
		if err != nil {
			t.Fatalf("failed to update user status: %v", err)
		}

		user, err := store.GetUser(pk)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}

		if user.Status != "banned" {
			t.Errorf("status not updated: %s", user.Status)
		}
	})

	t.Run("UpdateNonexistentUserStatus", func(t *testing.T) {
		err := store.UpdateUserStatus("nonexistent-pk", "banned")
		if err != ErrUserNotFound {
			t.Errorf("expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("ListUsers", func(t *testing.T) {
		// Create another user
		store.CreateUser("test-pk-2")

		users, err := store.ListUsers()
		if err != nil {
			t.Fatalf("failed to list users: %v", err)
		}

		if len(users) < 2 {
			t.Errorf("expected at least 2 users, got %d", len(users))
		}

		// Check that our test user is in the list
		found := false
		for _, user := range users {
			if user.PK == pk {
				found = true
				break
			}
		}
		if !found {
			t.Error("test user not found in list")
		}
	})
}

func TestMemoryStore_SessionOperations(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	session := &ZKSession{
		ID:              "test-session-id",
		PK:              "test-public-key",
		T:               []byte("commitment-point"),
		C:               []byte("challenge-scalar"),
		Timeslice:       time.Now().Truncate(time.Minute),
		ServerEphemeral: []byte("server-ephemeral-data"),
		JKT:             "test-jkt-thumbprint",
		Used:            false,
	}

	t.Run("CreateSession", func(t *testing.T) {
		err := store.CreateSession(session)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
	})

	t.Run("GetSession", func(t *testing.T) {
		retrievedSession, err := store.GetSession(session.ID)
		if err != nil {
			t.Fatalf("failed to get session: %v", err)
		}

		if retrievedSession.ID != session.ID {
			t.Errorf("wrong session ID: %s", retrievedSession.ID)
		}

		if retrievedSession.PK != session.PK {
			t.Errorf("wrong public key: %s", retrievedSession.PK)
		}

		if string(retrievedSession.T) != string(session.T) {
			t.Error("commitment point mismatch")
		}

		if string(retrievedSession.C) != string(session.C) {
			t.Error("challenge scalar mismatch")
		}

		if retrievedSession.JKT != session.JKT {
			t.Errorf("wrong JKT: %s", retrievedSession.JKT)
		}

		if retrievedSession.Used != session.Used {
			t.Errorf("wrong used status: %v", retrievedSession.Used)
		}
	})

	t.Run("GetNonexistentSession", func(t *testing.T) {
		_, err := store.GetSession("nonexistent-session")
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("MarkSessionUsed", func(t *testing.T) {
		err := store.MarkSessionUsed(session.ID)
		if err != nil {
			t.Fatalf("failed to mark session used: %v", err)
		}

		retrievedSession, err := store.GetSession(session.ID)
		if err != nil {
			t.Fatalf("failed to get session: %v", err)
		}

		if !retrievedSession.Used {
			t.Error("session should be marked as used")
		}

		// Marking as used again should fail
		err = store.MarkSessionUsed(session.ID)
		if err != ErrSessionUsed {
			t.Errorf("expected ErrSessionUsed, got %v", err)
		}
	})

	t.Run("MarkNonexistentSessionUsed", func(t *testing.T) {
		err := store.MarkSessionUsed("nonexistent-session")
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("GetSessionsByPK", func(t *testing.T) {
		// Create another session for the same PK
		session2 := &ZKSession{
			ID:              "test-session-id-2",
			PK:              "test-public-key",
			T:               []byte("commitment-point-2"),
			C:               []byte("challenge-scalar-2"),
			Timeslice:       time.Now().Truncate(time.Minute),
			ServerEphemeral: []byte("server-ephemeral-data-2"),
			JKT:             "test-jkt-thumbprint-2",
			Used:            false,
		}
		store.CreateSession(session2)

		sessions, err := store.GetSessionsByPK("test-public-key")
		if err != nil {
			t.Fatalf("failed to get sessions by PK: %v", err)
		}

		if len(sessions) < 2 {
			t.Errorf("expected at least 2 sessions, got %d", len(sessions))
		}

		// Check that both sessions are present
		foundIDs := make(map[string]bool)
		for _, s := range sessions {
			foundIDs[s.ID] = true
		}

		if !foundIDs[session.ID] {
			t.Error("first session not found")
		}

		if !foundIDs[session2.ID] {
			t.Error("second session not found")
		}
	})

	t.Run("GetExpiredSession", func(t *testing.T) {
		// Create an old session by modifying the created time
		oldSession := &ZKSession{
			ID:              "old-session",
			PK:              "test-public-key",
			T:               []byte("old-commitment"),
			C:               []byte("old-challenge"),
			Timeslice:       time.Now().Add(-10 * time.Minute),
			ServerEphemeral: []byte("old-ephemeral"),
			JKT:             "old-jkt",
			Used:            false,
		}

		store.CreateSession(oldSession)

		// Manually set creation time to old
		memStore := store
		memStore.mu.Lock()
		if session, exists := memStore.sessions["old-session"]; exists {
			session.CreatedAt = time.Now().Add(-10 * time.Minute)
		}
		memStore.mu.Unlock()

		_, err := store.GetSession("old-session")
		if err != ErrSessionExpired {
			t.Errorf("expected ErrSessionExpired, got %v", err)
		}
	})

	t.Run("CleanupExpiredSessions", func(t *testing.T) {
		// The cleanup should remove old sessions
		err := store.CleanupExpiredSessions(1 * time.Minute)
		if err != nil {
			t.Fatalf("failed to cleanup sessions: %v", err)
		}

		// Old session should be gone
		_, err = store.GetSession("old-session")
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound after cleanup, got %v", err)
		}
	})
}

func TestMemoryStore_DenylistOperations(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	pk := "test-banned-key"

	t.Run("AddToDenylist", func(t *testing.T) {
		err := store.AddToDenylist(pk)
		if err != nil {
			t.Fatalf("failed to add to denylist: %v", err)
		}
	})

	t.Run("IsInDenylist", func(t *testing.T) {
		banned, err := store.IsInDenylist(pk)
		if err != nil {
			t.Fatalf("failed to check denylist: %v", err)
		}

		if !banned {
			t.Error("key should be in denylist")
		}

		// Check non-banned key
		banned, err = store.IsInDenylist("not-banned-key")
		if err != nil {
			t.Fatalf("failed to check denylist: %v", err)
		}

		if banned {
			t.Error("key should not be in denylist")
		}
	})

	t.Run("ListDenylist", func(t *testing.T) {
		// Add another key
		store.AddToDenylist("another-banned-key")

		banned, err := store.ListDenylist()
		if err != nil {
			t.Fatalf("failed to list denylist: %v", err)
		}

		if len(banned) < 2 {
			t.Errorf("expected at least 2 banned keys, got %d", len(banned))
		}

		found := false
		for _, key := range banned {
			if key == pk {
				found = true
				break
			}
		}
		if !found {
			t.Error("test key not found in denylist")
		}
	})

	t.Run("RemoveFromDenylist", func(t *testing.T) {
		err := store.RemoveFromDenylist(pk)
		if err != nil {
			t.Fatalf("failed to remove from denylist: %v", err)
		}

		banned, err := store.IsInDenylist(pk)
		if err != nil {
			t.Fatalf("failed to check denylist: %v", err)
		}

		if banned {
			t.Error("key should not be in denylist after removal")
		}
	})
}

func TestMemoryStore_UtilityMethods(t *testing.T) {
	store := NewMemoryStore()

	t.Run("Ping", func(t *testing.T) {
		err := store.Ping()
		if err != nil {
			t.Errorf("ping should always succeed for memory store: %v", err)
		}
	})

	t.Run("Close", func(t *testing.T) {
		err := store.Close()
		if err != nil {
			t.Errorf("close should always succeed for memory store: %v", err)
		}
	})

	t.Run("Stats", func(t *testing.T) {
		// Create some test data
		store.CreateUser("test-user")
		store.AddToDenylist("banned-user")
		
		session := &ZKSession{
			ID:              "test-session",
			PK:              "test-user",
			T:               []byte("test"),
			C:               []byte("test"),
			Timeslice:       time.Now(),
			ServerEphemeral: []byte("test"),
			JKT:             "test",
			Used:            false,
		}
		store.CreateSession(session)

		memStore := store
		stats := memStore.Stats()

		if stats["users"] < 1 {
			t.Errorf("expected at least 1 user, got %d", stats["users"])
		}

		if stats["sessions"] < 1 {
			t.Errorf("expected at least 1 session, got %d", stats["sessions"])
		}

		if stats["denylist"] < 1 {
			t.Errorf("expected at least 1 denylist entry, got %d", stats["denylist"])
		}
	})
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	// Test concurrent user creation
	t.Run("ConcurrentUserCreation", func(t *testing.T) {
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func(id int) {
				defer func() { done <- true }()
				
				pk := fmt.Sprintf("concurrent-user-%d", id)
				err := store.CreateUser(pk)
				if err != nil {
					t.Errorf("failed to create user %d: %v", id, err)
				}

				user, err := store.GetUser(pk)
				if err != nil {
					t.Errorf("failed to get user %d: %v", id, err)
				}

				if user.PK != pk {
					t.Errorf("wrong PK for user %d: %s", id, user.PK)
				}
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	// Test concurrent session operations
	t.Run("ConcurrentSessionOperations", func(t *testing.T) {
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func(id int) {
				defer func() { done <- true }()

				session := &ZKSession{
					ID:              fmt.Sprintf("concurrent-session-%d", id),
					PK:              "test-user",
					T:               []byte(fmt.Sprintf("commitment-%d", id)),
					C:               []byte(fmt.Sprintf("challenge-%d", id)),
					Timeslice:       time.Now(),
					ServerEphemeral: []byte(fmt.Sprintf("ephemeral-%d", id)),
					JKT:             fmt.Sprintf("jkt-%d", id),
					Used:            false,
				}

				err := store.CreateSession(session)
				if err != nil {
					t.Errorf("failed to create session %d: %v", id, err)
				}

				retrievedSession, err := store.GetSession(session.ID)
				if err != nil {
					t.Errorf("failed to get session %d: %v", id, err)
				}

				if retrievedSession.ID != session.ID {
					t.Errorf("wrong session ID for session %d: %s", id, retrievedSession.ID)
				}
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}