
# icap-server

Simple ICAP Server Java Implementation

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

What things you need to install the software and how to install them.

```
Java JDK 1.8 or higher.
```

### Installing

Just clone this project on your favorite Java-Compatible IDE and have fun. 

## Available ICAP endpoints

Once started the server will listen on `127.0.0.1:1344` and the following endpoints are going to be available:

| URI  | Supported Methods |
| ------------- | ------------- |
| `/info`  | OPTIONS, RESPMOD  |
| `/echo`  | OPTIONS, REQMOD, RESPMOD | 
| `/virus_scan`  | OPTIONS, REQMOD, RESPMOD |

## Deployment

.

## Built With

* [Maven](https://maven.apache.org/) - Dependency Management

## Contributing

.

## Versioning

This project uses [SemVer](http://semver.org/) for versioning.

## Authors

* **Claudiney Nascimento** - *Initial work* - [claudineyns](https://github.com/claudineyns)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

* [RFC3507](https://www.ietf.org/rfc/rfc3507.txt)
