package types

type StringSet struct {
	items map[string]bool
}

func (s *StringSet) Add(item string) {
	s.items[item] = true
}

func (s *StringSet) Remove(item string) {
	delete(s.items, item)
}

func (s *StringSet) Contains(item string) bool {
	_, ok := s.items[item]
	return ok
}

func (s *StringSet) ContainsOne(items []string) bool {
	for _, item := range items {
		if s.Contains(item) {
			return true
		}
	}
	return false
}

func (s *StringSet) List() []string {
	var list []string
	for item := range s.items {
		list = append(list, item)
	}
	return list
}

func (s *StringSet) AddList(list []string) {
	for _, item := range list {
		s.Add(item)
	}
}

func NewSet() *StringSet {
	return &StringSet{
		items: make(map[string]bool),
	}
}

func NewSetFromList(list []string) *StringSet {
	s := NewSet()
	s.AddList(list)
	return s
}
