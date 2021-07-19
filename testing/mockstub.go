package testing

import (
	"container/list"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/Bloxico/sl-v3-be-hlf-util-helpers/models"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
	"github.com/hyperledger/fabric-protos-go/peer"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/msp"
	gologging "github.com/op/go-logging"
	"github.com/pkg/errors"
	"github.com/s7techlab/cckit/convert"
)

const EventChannelBufferSize = 100

var (
	// ErrChaincodeNotExists occurs when attempting to invoke a nonexostent external chaincode
	ErrChaincodeNotExists = errors.New(`chaincode not exists`)
	// ErrUnknownFromArgsType occurs when attempting to set unknown args in From func
	ErrUnknownFromArgsType = errors.New(`unknown args type to cckit.MockStub.From func`)
	// ErrKeyAlreadyExistsInTransientMap occurs when attempting to set existing key in transient map
	ErrKeyAlreadyExistsInTransientMap = errors.New(`key already exists in transient map`)
)

type StateItem struct {
	Key   string
	Value []byte
}

// MockStub replacement of shim.MockStub with creator mocking facilities
type MockStub struct {
	shimtest.MockStub
	StateBuffer                 []*StateItem // buffer for state changes during transaction
	cc                          shim.Chaincode
	m                           sync.Mutex
	mockCreator                 []byte
	transient                   map[string][]byte
	ClearCreatorAfterInvoke     bool
	_args                       [][]byte
	InvokablesFull              map[string]*MockStub        // invokable this version of MockStub
	creatorTransformer          CreatorTransformer          // transformer for tx creator data, used in From func
	ChaincodeEvent              *peer.ChaincodeEvent        // event in last tx
	chaincodeEventSubscriptions []chan *peer.ChaincodeEvent // multiple event subscriptions
	PrivateKeys                 map[string]*list.List
}

type CreatorTransformer func(...interface{}) (mspID string, certPEM []byte, err error)

// NewMockStub creates chaincode imitation
func NewMockStub(name string, cc shim.Chaincode) *MockStub {
	return &MockStub{
		MockStub: *shimtest.NewMockStub(name, cc),
		cc:       cc,
		// by default tx creator data and transient map are cleared after each cc method query/invoke
		ClearCreatorAfterInvoke: true,
		InvokablesFull:          make(map[string]*MockStub),
		PrivateKeys:             make(map[string]*list.List),
	}
}

// PutState wrapped functions puts state items in queue and dumps
// to state after invocation
func (stub *MockStub) PutState(key string, value []byte) error {
	if stub.TxID == "" {
		return errors.New("cannot PutState without a transactions - call stub.MockTransactionStart()?")
	}

	stub.StateBuffer = append(stub.StateBuffer, &StateItem{
		Key:   key,
		Value: value,
	})

	return nil
}

// GetArgs mocked args
func (stub *MockStub) GetArgs() [][]byte {
	return stub._args
}

// SetArgs set mocked args
func (stub *MockStub) SetArgs(args [][]byte) {
	stub._args = args
}

// SetEvent sets chaincode event
func (stub *MockStub) SetEvent(name string, payload []byte) error {
	if name == "" {
		return errors.New("event name can not be nil string")
	}

	stub.ChaincodeEvent = &peer.ChaincodeEvent{EventName: name, Payload: payload}
	return nil
}

func (stub *MockStub) EventSubscription() chan *peer.ChaincodeEvent {
	subscription := make(chan *peer.ChaincodeEvent, EventChannelBufferSize)
	stub.chaincodeEventSubscriptions = append(stub.chaincodeEventSubscriptions, subscription)
	return subscription
}

// ClearEvents clears chaincode events channel
func (stub *MockStub) ClearEvents() {
	for len(stub.ChaincodeEventsChannel) > 0 {
		<-stub.ChaincodeEventsChannel
	}
}

// GetStringArgs get mocked args as strings
func (stub *MockStub) GetStringArgs() []string {
	args := stub.GetArgs()
	strargs := make([]string, 0, len(args))
	for _, barg := range args {
		strargs = append(strargs, string(barg))
	}
	return strargs
}

// MockPeerChaincode link to another MockStub
func (stub *MockStub) MockPeerChaincode(invokableChaincodeName string, otherStub *MockStub) {
	stub.InvokablesFull[invokableChaincodeName] = otherStub
}

// MockedPeerChaincodes returns names of mocked chaincodes, available for invoke from current stub
func (stub *MockStub) MockedPeerChaincodes() []string {
	keys := make([]string, 0)
	for k := range stub.InvokablesFull {
		keys = append(keys, k)
	}
	return keys
}

// InvokeChaincode using another MockStub
func (stub *MockStub) InvokeChaincode(chaincodeName string, args [][]byte, channel string) peer.Response {
	// Internally we use chaincode name as a composite name
	ccName := chaincodeName
	if channel != "" {
		chaincodeName = chaincodeName + "/" + channel
	}

	otherStub, exists := stub.InvokablesFull[chaincodeName]
	if !exists {
		return shim.Error(fmt.Sprintf(
			`%s	: try to invoke chaincode "%s" in channel "%s" (%s). Available mocked chaincodes are: %s`,
			ErrChaincodeNotExists, ccName, channel, chaincodeName, stub.MockedPeerChaincodes()))
	}

	res := otherStub.MockInvoke(stub.TxID, args)
	return res
}

// GetFunctionAndParameters mocked
func (stub *MockStub) GetFunctionAndParameters() (function string, params []string) {
	allargs := stub.GetStringArgs()
	function = ""
	params = []string{}
	if len(allargs) >= 1 {
		function = allargs[0]
		params = allargs[1:]
	}
	return
}

// RegisterCreatorTransformer  that transforms creator data to MSP_ID and X.509 certificate
func (stub *MockStub) RegisterCreatorTransformer(creatorTransformer CreatorTransformer) *MockStub {
	stub.creatorTransformer = creatorTransformer
	return stub
}

// MockCreator of tx
func (stub *MockStub) MockCreator(mspID string, certPEM []byte) {
	stub.mockCreator, _ = msp.NewSerializedIdentity(mspID, certPEM)
}

func (stub *MockStub) generateTxUID() string {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		panic(err)
	}
	return fmt.Sprintf("0x%x", id)
}

// Init func of chaincode - sugared version with autogenerated tx uuid
func (stub *MockStub) Init(iargs ...interface{}) peer.Response {
	args, err := convert.ArgsToBytes(iargs...)
	if err != nil {
		return shim.Error(err.Error())
	}

	return stub.MockInit(stub.generateTxUID(), args)
}

// InitBytes init func with ...[]byte args
func (stub *MockStub) InitBytes(args ...[]byte) peer.Response {
	return stub.MockInit(stub.generateTxUID(), args)
}

// MockInit mocked init function
func (stub *MockStub) MockInit(uuid string, args [][]byte) peer.Response {

	stub.SetArgs(args)

	stub.MockTransactionStart(uuid)
	res := stub.cc.Init(stub)
	stub.MockTransactionEnd(uuid)

	return res
}

func (stub *MockStub) DumpStateBuffer() {
	// dump state buffer to state
	for i := range stub.StateBuffer {
		s := stub.StateBuffer[i]
		_ = stub.MockStub.PutState(s.Key, s.Value)
	}
	stub.StateBuffer = nil

	if stub.ChaincodeEvent != nil {
		// send only last event
		for _, sub := range stub.chaincodeEventSubscriptions {
			sub <- stub.ChaincodeEvent
		}

		// actually no chances to have error here
		_ = stub.MockStub.SetEvent(stub.ChaincodeEvent.EventName, stub.ChaincodeEvent.Payload)
	}
}

// MockQuery
func (stub *MockStub) MockQuery(uuid string, args [][]byte) peer.Response {
	return stub.MockInvoke(uuid, args)
}

func (stub *MockStub) MockTransactionStart(uuid string) {
	//empty event
	stub.ChaincodeEvent = nil

	// empty state buffer
	stub.StateBuffer = nil

	stub.MockStub.MockTransactionStart(uuid)
}

func (stub *MockStub) MockTransactionEnd(uuid string) {

	stub.DumpStateBuffer()

	stub.MockStub.MockTransactionEnd(uuid)

	if stub.ClearCreatorAfterInvoke {
		stub.mockCreator = nil
		stub.transient = nil
	}
}

// MockInvoke
func (stub *MockStub) MockInvoke(uuid string, args [][]byte) peer.Response {
	stub.m.Lock()
	defer stub.m.Unlock()

	// this is a hack here to set MockStub.args, because its not accessible otherwise
	stub.SetArgs(args)

	// now do the invoke with the correct stub
	stub.MockTransactionStart(uuid)
	res := stub.cc.Invoke(stub)
	stub.MockTransactionEnd(uuid)

	return res
}

// Invoke sugared invoke function with autogenerated tx uuid
func (stub *MockStub) Invoke(funcName string, iargs ...interface{}) peer.Response {
	fargs, err := convert.ArgsToBytes(iargs...)
	if err != nil {
		return shim.Error(err.Error())
	}
	args := append([][]byte{[]byte(funcName)}, fargs...)
	return stub.InvokeBytes(args...)
}

// InvokeByte mock invoke with autogenerated tx uuid
func (stub *MockStub) InvokeBytes(args ...[]byte) peer.Response {
	return stub.MockInvoke(stub.generateTxUID(), args)
}

// QueryBytes mock query with autogenerated tx uuid
func (stub *MockStub) QueryBytes(args ...[]byte) peer.Response {
	return stub.MockQuery(stub.generateTxUID(), args)
}

func (stub *MockStub) Query(funcName string, iargs ...interface{}) peer.Response {
	return stub.Invoke(funcName, iargs...)
}

// GetCreator mocked
func (stub *MockStub) GetCreator() ([]byte, error) {
	return stub.mockCreator, nil
}

// From mock tx creator
func (stub *MockStub) From(txCreator ...interface{}) *MockStub {

	var mspID string
	var certPEM []byte
	var err error

	if stub.creatorTransformer != nil {
		mspID, certPEM, err = stub.creatorTransformer(txCreator...)
	} else {
		mspID, certPEM, err = TransformCreator(txCreator...)
	}

	if err != nil {
		panic(err)
	}
	stub.MockCreator(mspID, certPEM)
	return stub
}

func (stub *MockStub) GetTransient() (map[string][]byte, error) {
	return stub.transient, nil
}

// WithTransient sets transient map
func (stub *MockStub) WithTransient(transient map[string][]byte) *MockStub {
	stub.transient = transient
	return stub
}

// AddTransient adds key-value pairs to transient map
func (stub *MockStub) AddTransient(transient map[string][]byte) *MockStub {
	if stub.transient == nil {
		stub.transient = make(map[string][]byte)
	}
	for k, v := range transient {
		if _, ok := stub.transient[k]; ok {
			panic(ErrKeyAlreadyExistsInTransientMap)
		}
		stub.transient[k] = v
	}
	return stub
}

// At mock tx timestamp
//func (stub *MockStub) At(txTimestamp *timestamp.Timestamp) *MockStub {
//	stub.TxTimestamp = txTimestamp
//	return stub
//}

// DelPrivateData mocked
func (stub *MockStub) DelPrivateData(collection string, key string) error {
	m, in := stub.PvtState[collection]
	if !in {
		return errors.Errorf("Collection %s not found.", collection)
	}

	if _, ok := m[key]; !ok {
		return errors.Errorf("Key %s not found.", key)
	}
	delete(m, key)

	for elem := stub.PrivateKeys[collection].Front(); elem != nil; elem = elem.Next() {
		if strings.Compare(key, elem.Value.(string)) == 0 {
			stub.PrivateKeys[collection].Remove(elem)
		}
	}
	return nil
}

type PrivateMockStateRangeQueryIterator struct {
	Closed     bool
	Stub       *MockStub
	StartKey   string
	EndKey     string
	Current    *list.Element
	Collection string
}

// Logger for the shim package.
var mockLogger = gologging.MustGetLogger("mock")

// HasNext returns true if the range query iterator contains additional keys
// and values.
func (iter *PrivateMockStateRangeQueryIterator) HasNext() bool {
	if iter.Closed {
		// previously called Close()
		return false
	}

	if iter.Current == nil {
		return false
	}

	current := iter.Current
	for current != nil {
		// if this is an open-ended query for all keys, return true
		if iter.StartKey == "" && iter.EndKey == "" {
			return true
		}
		comp1 := strings.Compare(current.Value.(string), iter.StartKey)
		comp2 := strings.Compare(current.Value.(string), iter.EndKey)
		if comp1 >= 0 {
			if comp2 < 0 {
				return true
			} else {
				return false

			}
		}
		current = current.Next()
	}

	// we've reached the end of the underlying values
	return false
}

// Next returns the next key and value in the range query iterator.
func (iter *PrivateMockStateRangeQueryIterator) Next() (*queryresult.KV, error) {
	if iter.Closed {
		err := errors.New("PrivateMockStateRangeQueryIterator.Next() called after Close()")
		return nil, err
	}

	if !iter.HasNext() {
		err := errors.New("PrivateMockStateRangeQueryIterator.Next() called when it does not HaveNext()")
		return nil, err
	}

	for iter.Current != nil {
		comp1 := strings.Compare(iter.Current.Value.(string), iter.StartKey)
		comp2 := strings.Compare(iter.Current.Value.(string), iter.EndKey)
		// compare to start and end keys. or, if this is an open-ended query for
		// all keys, it should always return the key and value
		if (comp1 >= 0 && comp2 < 0) || (iter.StartKey == "" && iter.EndKey == "") {
			key := iter.Current.Value.(string)
			value, err := iter.Stub.GetPrivateData(iter.Collection, key)
			iter.Current = iter.Current.Next()
			return &queryresult.KV{Key: key, Value: value}, err
		}
		iter.Current = iter.Current.Next()
	}
	return nil, errors.New("PrivateMockStateRangeQueryIterator.Next() went past end of range")
}

// Close closes the range query iterator. This should be called when done
// reading from the iterator to free up resources.
func (iter *PrivateMockStateRangeQueryIterator) Close() error {
	if iter.Closed {
		return errors.New("PrivateMockStateRangeQueryIterator.Close() called after Close()")
	}

	iter.Closed = true
	return nil
}

func NewPrivateMockStateRangeQueryIterator(stub *MockStub, collection string, startKey string, endKey string) *PrivateMockStateRangeQueryIterator {

	if _, ok := stub.PrivateKeys[collection]; !ok {
		stub.PrivateKeys[collection] = list.New()
	}
	iter := new(PrivateMockStateRangeQueryIterator)
	iter.Closed = false
	iter.Stub = stub
	iter.StartKey = startKey
	iter.EndKey = endKey
	iter.Current = stub.PrivateKeys[collection].Front()
	iter.Collection = collection

	return iter
}

// PutPrivateData mocked
func (stub *MockStub) PutPrivateData(collection string, key string, value []byte) error {
	if _, in := stub.PvtState[collection]; !in {
		stub.PvtState[collection] = make(map[string][]byte)
	}
	stub.PvtState[collection][key] = value

	if _, ok := stub.PrivateKeys[collection]; !ok {
		stub.PrivateKeys[collection] = list.New()
	}

	for elem := stub.PrivateKeys[collection].Front(); elem != nil; elem = elem.Next() {
		elemValue := elem.Value.(string)
		comp := strings.Compare(key, elemValue)
		if comp < 0 {
			// key < elem, insert it before elem
			stub.PrivateKeys[collection].InsertBefore(key, elem)
			break
		} else if comp == 0 {
			// keys exists, no need to change
			break
		} else { // comp > 0
			// key > elem, keep looking unless this is the end of the list
			if elem.Next() == nil {
				stub.PrivateKeys[collection].PushBack(key)
				break
			}
		}
	}

	// special case for empty Keys list
	if stub.PrivateKeys[collection].Len() == 0 {
		stub.PrivateKeys[collection].PushFront(key)
	}

	return nil
}

const maxUnicodeRuneValue = utf8.MaxRune

// GetPrivateDataByPartialCompositeKey mocked
func (stub *MockStub) GetPrivateDataByPartialCompositeKey(collection, objectType string, attributes []string) (shim.StateQueryIteratorInterface, error) {
	partialCompositeKey, err := stub.CreateCompositeKey(objectType, attributes)
	if err != nil {
		return nil, err
	}
	return NewPrivateMockStateRangeQueryIterator(stub, collection, partialCompositeKey, partialCompositeKey+string(maxUnicodeRuneValue)), nil
}

// ############################# ADDED

type MockStateQueryResultIterator struct {
	Closed  bool
	Stub    *MockStub
	Current *list.Element
}

func NewMockStateQueryResultIterator(stub *MockStub, collection list.List) *MockStateQueryResultIterator {
	iter := new(MockStateQueryResultIterator)
	iter.Closed = false
	iter.Stub = stub
	iter.Current = collection.Front()
	return iter
}

func (iter *MockStateQueryResultIterator) Close() error {
	if iter.Closed {
		err := errors.New("MockStateQueryResultIterator.Close() called after Close()")
		mockLogger.Errorf("%+v", err)
		return err
	}

	iter.Closed = true
	return nil
}

// HasNext returns true if the query iterator contains additional keys and values.
func (iter *MockStateQueryResultIterator) HasNext() bool {
	if iter.Closed {
		mockLogger.Debug("HasNext() but already closed")
		return false
	}

	if iter.Current == nil {
		mockLogger.Error("HasNext() couldn't get Current")
		return false
	}

	return iter.Current != nil
}

// Next returns the next key and value in the range query iterator.
func (iter *MockStateQueryResultIterator) Next() (*queryresult.KV, error) {
	if iter.Closed {
		err := errors.New("MockStateQueryResultIterator.Next() called after Close()")
		mockLogger.Errorf("%+v", err)
		return nil, err
	}

	if !iter.HasNext() {
		err := errors.New("MockStateQueryResultIterator.Next() called when it does not HaveNext()")
		mockLogger.Errorf("%+v", err)
		return nil, err
	}

	for iter.Current != nil {
		currentElem := iter.Current.Value.(map[string]interface{})
		currentValueBytes, err := json.Marshal(currentElem["key"])
		if err != nil {
			err := errors.New("MockStateQueryResultIterator.Next() error reading data")
			mockLogger.Errorf("%+v", err)
			return nil, err
		}
		iter.Current = iter.Current.Next()
		return &queryresult.KV{Key: string(currentValueBytes), Value: currentElem["value"].([]byte)}, nil
	}

	err := errors.New("MockStateQueryResultIterator.Next() went past end of range")
	mockLogger.Errorf("%+v", err)
	return nil, err
}

func IsString(data interface{}) bool {
	return reflect.TypeOf(data).Kind() == reflect.String
}

func IsMap(data interface{}) bool {
	return reflect.TypeOf(data).Kind() == reflect.Map
}

func IsArray(data interface{}) bool {
	return reflect.TypeOf(data).Kind() == reflect.Array
}

func ValidateProperty(selectorValue interface{}, originalValue interface{}) (bool, error) {
	if !IsMap(selectorValue) {
		// Selector property is NOT object
		return originalValue == selectorValue, nil
	}

	// Selector property is object
	selectorValueMap := selectorValue.(map[string]interface{})

	// Validate regex selector
	if regexValue, ok := selectorValueMap["$regex"]; ok {
		regex := regexp.MustCompile(regexValue.(string))
		return regex.MatchString(originalValue.(string)), nil
	}

	// Validate equals selector
	if equalsValue, ok := selectorValueMap["$eq"]; ok {
		return originalValue == equalsValue, nil
	}

	// Validate in selector
	if inValues, ok := selectorValueMap["$in"]; ok {

		inValuesBytes, err := json.Marshal(inValues)
		if err != nil {
			return false, err
		}

		if !IsString(originalValue) {
			// Expected array of string, other not implemented
			return false, errors.New("Not supported")
		}

		inValuesArray := []string{}
		if err := json.Unmarshal(inValuesBytes, &inValuesArray); err != nil {
			return false, err
		}

		for _, inValue := range inValuesArray {
			if inValue == originalValue {
				return true, nil
			}
		}
		return false, nil
	}

	if IsArray(originalValue) {

		// Selector property is object
		originalValueArray := originalValue.([]map[string]interface{})

		if elemMatch, ok := selectorValueMap["$elemMatch"]; ok {
			elemMatchData := elemMatch.(map[string]interface{})

			for _, originalValue := range originalValueArray {
				if _, ok := elemMatchData["txID"]; !ok {
					return false, errors.New("Not supported")
				}

				inValueData := elemMatchData["txID"].(map[string]interface{})

				if _, ok := inValueData["$in"]; !ok {
					return false, errors.New("Not supported")
				}

				inValueString := inValueData["$in"].(string)

				inValuesBytes, err := json.Marshal(elemMatchData[inValueString])
				if err != nil {
					return false, err
				}

				inValuesArray := []string{}
				if err := json.Unmarshal(inValuesBytes, &inValuesArray); err != nil {
					return false, err
				}

				if !IsString(originalValue) {
					// Expected array of string, other not implemented
					return false, errors.New("Not supported")
				}

				for _, inValue := range inValuesArray {
					if inValue == originalValue["txID"] {
						return true, nil
					}
				}
			}
			return false, nil
		}
	}

	return false, errors.New("Not implemented selector")
}

func GetSortPropertyAndDirection(sortElement interface{}) (string, string) {
	if !IsMap(sortElement) {
		// Selector property is NOT map

		// Default sort direction is ASC
		return sortElement.(string), "asc"
	}

	// Selector property is map
	selectorValueMap := sortElement.(map[string]interface{})

	for sortProperty, sortDirection := range selectorValueMap {
		if !IsString(sortDirection) {
			panic("sort object direction is not string")
		}
		return sortProperty, sortDirection.(string)
	}

	panic("Empty map for sort")
}

func (stub *MockStub) GetQueryResult(query string) (shim.StateQueryIteratorInterface, error) {
	// Read query string as object
	queryObject := map[string]interface{}{}
	if err := json.Unmarshal([]byte(query), &queryObject); err != nil {
		mockLogger.Errorf("%+v", err)
		return nil, err
	}

	// Read selector as map
	selector := queryObject["selector"].(map[string]interface{})

	// Read sort as map
	sortElements := []interface{}{}
	if queryObject["sort"] != nil {
		sortElements = queryObject["sort"].([]interface{})
	}

	// First filter state for conditions from selector
	queriedElements := []map[string]interface{}{}

OUTER:
	for key, value := range stub.State {
		for selectorKey, selectorValue := range selector {

			queryRes, err := QueryData(key, selectorKey, value, selectorValue)
			if err != nil {
				mockLogger.Errorf("%+v", err)
				return nil, err
			}

			if !queryRes {
				continue OUTER
			}
		}

		queriedElements = append(queriedElements, map[string]interface{}{
			"key":   key,
			"value": value,
		})
	}

	// Sort filtered data
	for _, sortElem := range sortElements {
		sortProperty, sortDirection := GetSortPropertyAndDirection(sortElem)
		queriedElements = SortData(sortProperty, sortDirection, queriedElements)
	}

	// Populate response with sorted, filtered data
	filteredElements := list.New()
	for _, data := range queriedElements {
		filteredElements.PushBack(data)
	}

	return NewMockStateQueryResultIterator(stub, *filteredElements), nil
}

func (stub *MockStub) GetQueryResultWithPagination(query string, pageSize int32, bookmark string) (shim.StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {

	// Read query string as object
	queryObject := map[string]interface{}{}
	if err := json.Unmarshal([]byte(query), &queryObject); err != nil {
		mockLogger.Errorf("%+v", err)
		return nil, nil, err
	}

	// Read selector as map
	selector := queryObject["selector"].(map[string]interface{})

	// Read sort as map
	sortElements := []interface{}{}
	if queryObject["sort"] != nil {
		sortElements = queryObject["sort"].([]interface{})
	}

	// First filter state for conditions from selector
	queriedElements := []map[string]interface{}{}
OUTER:
	for key, value := range stub.State {
		for selectorKey, selectorValue := range selector {
			queryRes, err := QueryData(key, selectorKey, value, selectorValue)
			if err != nil {
				mockLogger.Errorf("%+v", err)
				return nil, nil, err
			}

			if !queryRes {
				continue OUTER
			}
		}

		queriedElements = append(queriedElements, map[string]interface{}{
			"key":   key,
			"value": value,
		})
	}

	// Sort filtered data
	for _, sortElem := range sortElements {
		sortProperty, sortDirection := GetSortPropertyAndDirection(sortElem)
		queriedElements = SortData(sortProperty, sortDirection, queriedElements)
	}

	// Populate response with sorted, filtered data
	// Calculate bookmark and count of data for this page
	filteredElements := list.New()
	count := 0
	var newBookmark string
	foundFirstOnPage := false
	for index, data := range queriedElements {

		if bookmark == data["key"].(string) {
			foundFirstOnPage = true
		}

		if bookmark != "" && !foundFirstOnPage {
			continue
		}

		count++
		filteredElements.PushBack(data)

		if count == int(pageSize) || len(queriedElements)-1 == index {
			nextIndex := index + 1
			if len(queriedElements) <= nextIndex {
				newBookmark = "" // TODO: Check this
				break
			}
			newBookmark = queriedElements[nextIndex]["key"].(string)
			break
		}
	}

	metadata := pb.QueryResponseMetadata{
		FetchedRecordsCount: int32(count),
		Bookmark:            newBookmark,
	}

	return NewMockStateQueryResultIterator(stub, *filteredElements), &metadata, nil
}

// ########### MODEL MOCK ###########

type ModelMock interface {
	query(selectorKey string, selectorValue interface{}) (bool, error)
	sort(nextObj ModelMock, sortKey, sortDirection string) bool
}

func CreateModelObject(key string, value []byte) ModelMock {
	if strings.Contains(key, "eCommerceID~affiliateID") {

		affiliate := AffiliateMock{}
		if err := json.Unmarshal(value, &affiliate); err != nil {
			mockLogger.Errorf("%+v", err)
			panic("Error reading affiliate data")
		}
		return affiliate

	} else if strings.Contains(key, "transaction") {

		transaction := TransactionMock{}
		if err := json.Unmarshal(value, &transaction); err != nil {
			mockLogger.Errorf("%+v", err)
			panic("Error reading transaction data")
		}
		return transaction
	}

	panic("Not implemented model object")
}

func QueryData(stubKey, selectorKey string, stubValue []byte, selectorValue interface{}) (bool, error) {
	modelObject := CreateModelObject(stubKey, stubValue)
	return modelObject.query(selectorKey, selectorValue)
}

func SortData(sortKey, sortDirection string, elementsForSort []map[string]interface{}) []map[string]interface{} {
	sort.Slice(elementsForSort, func(i, j int) bool {
		obj1 := CreateModelObject(elementsForSort[i]["key"].(string), elementsForSort[i]["value"].([]byte))
		obj2 := CreateModelObject(elementsForSort[j]["key"].(string), elementsForSort[j]["value"].([]byte))

		return obj1.sort(obj2, sortKey, sortDirection)
	})

	return elementsForSort
}

// ########### AFFILIATE MOCK ###########

type AffiliateMock struct {
	models.Affiliate
}

// Query different affiliate properties used in affiliate chaincode
func (affiliate AffiliateMock) query(selectorKey string, selectorValue interface{}) (bool, error) {
	switch selectorKey {
	case "docType":
		return ValidateProperty(selectorValue, string(affiliate.DocType))
	case "path":
		return ValidateProperty(selectorValue, string(affiliate.Path))
	case "parentID":
		return ValidateProperty(selectorValue, string(affiliate.ParentID))
	case "affiliateID":
		return ValidateProperty(selectorValue, string(affiliate.AffiliateID))
	default:
		return false, errors.New("Wrong selector key")
	}
}

// Sort affiliates by given sort properties
func (affiliate AffiliateMock) sort(nextObj ModelMock, sortKey, sortDirection string) bool {
	switch sortKey {
	case "createdAt":
		if sortDirection == "asc" {
			return affiliate.CreatedAt < nextObj.(AffiliateMock).CreatedAt
		} else {
			return affiliate.CreatedAt > nextObj.(AffiliateMock).CreatedAt
		}
	case "level":
		if sortDirection == "asc" {
			return affiliate.Level < nextObj.(AffiliateMock).Level
		} else {
			return affiliate.Level > nextObj.(AffiliateMock).Level
		}
	default:
		panic("Not implemented sort key")
	}
}

// ########### TRANSACTION MOCK ###########

type TransactionMock struct {
	models.Transaction
}

// Query different transaction properties used in transaction chaincode
func (transaction TransactionMock) query(selectorKey string, selectorValue interface{}) (bool, error) {
	switch selectorKey {
	case "docType":
		return ValidateProperty(selectorValue, string(transaction.DocType))
	case "senders":
		return ValidateProperty(selectorValue, transaction.Senders)
	case "receivers":
		return ValidateProperty(selectorValue, transaction.Receivers)
	default:
		return false, errors.New("Wrong selector key")
	}
}

// Sort transactions by given sort properties
func (transaction TransactionMock) sort(nextObj ModelMock, sortKey, sortDirection string) bool {
	switch sortKey {
	case "createdAt":
		if sortDirection == "asc" {
			return transaction.CreatedAt < nextObj.(TransactionMock).CreatedAt
		} else {
			return transaction.CreatedAt > nextObj.(TransactionMock).CreatedAt
		}
	default:
		panic("Not implemented sort key")
	}
}
