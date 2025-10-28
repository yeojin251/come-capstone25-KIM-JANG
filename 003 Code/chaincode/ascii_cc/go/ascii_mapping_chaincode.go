package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing encrypted ASCII mappings
type SmartContract struct {
	contractapi.Contract
}

// MappingData represents the structure stored on the ledger
type MappingData struct {
	UserID string `json:"userID"`
	EncryptedMapping string `json:"encryptedMapping"` // AES-256 encrypted JSON string
}


// SetMapping registers a new encrypted ASCII mapping for a user
func (s *SmartContract) SetMapping(ctx contractapi.TransactionContextInterface, userID string, encryptedMapping string) error {
	if userID == "" || encryptedMapping == "" {
		return fmt.Errorf("userID and encryptedMapping cannot be empty")
	}

	mapping := MappingData{
		UserID: userID,
		EncryptedMapping: encryptedMapping,
	}

	// Serialize to JSON
	mappingBytes, err := json.Marshal(mapping)
	if err != nil {
		return fmt.Errorf("failed to marshal mapping data: %v", err)
	}

	// Store in world state
	return ctx.GetStub().PutState(userID, mappingBytes)
}

// UpdateMapping updates an existing encrypted ASCII mapping for a user
func (s *SmartContract) UpdateMapping(ctx contractapi.TransactionContextInterface, userID string, newEncryptedMapping string) error {
	exists, err := s.MappingExists(ctx, userID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("mapping for userID %s does not exist", userID)
	}

	mapping := MappingData{
		UserID:           userID,
		EncryptedMapping: newEncryptedMapping,
	}

	mappingBytes, err := json.Marshal(mapping)
	if err != nil {
		return fmt.Errorf("failed to marshal updated mapping: %v", err)
	}

	return ctx.GetStub().PutState(userID, mappingBytes)
}

// GetMapping retrieves the encrypted ASCII mapping for a user
func (s *SmartContract) GetMapping(ctx contractapi.TransactionContextInterface, userID string) (*MappingData, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}

	mappingBytes, err := ctx.GetStub().GetState(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if mappingBytes == nil {
		return nil, fmt.Errorf("no mapping found for userID: %s", userID)
	}

	var mapping MappingData
	err = json.Unmarshal(mappingBytes, &mapping)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal mapping data: %v", err)
	}

	return &mapping, nil
}
// 모든 사용자 매핑 리스트 가져오기
func (s *SmartContract) GetAllMappings(ctx contractapi.TransactionContextInterface) ([]*MappingData, error) {
    resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
    if err != nil {
        return nil, err
    }
    defer resultsIterator.Close()

    var mappings []*MappingData
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, err
        }

        var mapping MappingData
        err = json.Unmarshal(queryResponse.Value, &mapping)
        if err != nil {
            return nil, err
        }
        mappings = append(mappings, &mapping)
    }

    return mappings, nil
}

// 특정 사용자 매핑 삭제
func (s *SmartContract) DeleteMapping(ctx contractapi.TransactionContextInterface, userID string) error {
    exists, err := s.MappingExists(ctx, userID)
    if err != nil {
        return err
    }
    if !exists {
        return fmt.Errorf("mapping for userID %s does not exist", userID)
    }

    return ctx.GetStub().DelState(userID)
}

func (s *SmartContract) MappingExists(ctx contractapi.TransactionContextInterface, userID string) (bool, error) {
    data, err := ctx.GetStub().GetState(userID)
    if err != nil {
        return false, err
    }
    return data != nil, nil
}


func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		panic(fmt.Sprintf("Error creating chaincode: %v", err))
	}

	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("Error starting chaincode: %v", err))
	}
}
