## How to contribute
- First, fork this repository into your Github account
- Second, clone repository
- Finaly, writing code push and PR to me

## Writing code
I checking the quality of code through Codacy when PR/Merge/Push. If you want to consider code quality in advance, please check the link below (not perfect, but very helpful).

https://goreportcard.com/report/github.com/hahwul/dalfox

e.g: `https://goreportcard.com/report/github.com/{your github account}/dalfox`

## Build
```
go build
```

## Case study
### How to add testing vector of XSS
- Add new vector to https://github.com/hahwul/dalfox/blob/master/pkg/scanning/payload.go
- Optimize but can affect performance, so please add a general and non-overlapping pattern.

### How to add new entity(e.g event handler)
- Add new pattern to https://github.com/hahwul/dalfox/blob/master/pkg/scanning/entity.go
