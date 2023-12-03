package index

import (
    "bufio"
    "io"
)

type IndexStreamIterator struct {
    parser func(string) interface{}
    file   io.ReadCloser
    scanner *bufio.Scanner
}

func NewIndexStreamIterator(file io.ReadCloser, parser func(string) interface{}) *IndexStreamIterator {
    return &IndexStreamIterator{
        parser: parser,
        file:   file,
        scanner: bufio.NewScanner(file),
    }
}

func (it *IndexStreamIterator) Close() {
    if it.file != nil {
        it.file.Close()
        it.file = nil
    }
}

func (it *IndexStreamIterator) Next() (interface{}, error) {
    if !it.scanner.Scan() {
        err := it.scanner.Err()
        if err == nil {
            return nil, io.EOF
        }
        return nil, err
    }

    line := it.scanner.Text()
    node := it.parser(line)
    if node != nil {
        return node, nil
    }

    return it.Next()
}
