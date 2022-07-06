package client

func SplitChunks(str string, chunkSize int) []string {
	chunks := make([]string, 0, (len(str)-1)/chunkSize+1)
	length, start := 0, 0

	for i := range str {
		if length == chunkSize {
			chunks = append(chunks, str[start:i])
			length = 0
			start = i
		}
		length++
	}
	chunks = append(chunks, str[start:])
	return chunks
}
