# Learning Tools Interoperability (LTI) Library for Learning Tools

> This Go-based library allows learning tool developers to easily connect their learning tools with a learning platform.
>
> For an example tool, see [lti-example](https://github.com/macewan-cs/lti-example).

## Table of Contents

- [General Information](#General-Information)
- [Technologies Used](#Technologies-Used)
- [Features](#Features)
- [Installation](#Installation)
- [Project Status](#Project-Status)
- [Future Work](#Future-Work)
- [Acknowledgements](#Acknowledgements)
- [Contact](#Contact)
- [License](#License)

## General Information

The [IMS Global Learning Consortium](http://www.imsglobal.org/) developed the [Learning Tools Interoperability (LTI)](https://www.imsglobal.org/activity/learning-tools-interoperability) specification to formalize communication between learning tools and learning platforms.
This project partially implements version 1.3 of the specification for developers for Go-based learning tools.
It simplifies integration with the LTI modified OIDC login flow, the tool launch, and the subsequent access to LTI services.

## Technologies Used

- Go - version 1.16
- [https://github.com/google/uuid](https://github.com/google/uuid) - version 1.2.0
- [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) - version 1.2.1

## Features

- Flexible options for storing data
- Simple functions and methods for integrating into your existing tool code
- Use of standard Go types where possible

## Installation

`go get github.com/macewan-cs/lti`

## Project Status

This project is under active development.
At this time, the functionality is not stable and we will almost certainly introduce breaking changes.

## Future Work

Many details from the IMS LTI 1.3 specification are unimplemented.
Some of the key areas of future work include:

- Deep linking

## Acknowledgements

This project is the answer to our need to connect eSubmit (https://esubmit.cs.macewan.ca) to Moodle.
Thank you to the developers of the PHP-based LTI 1.3 Advantage [reference library](https://github.com/IMSGlobal/lti-1-3-php-library), which served as a reference during our development.

Funding for this project was provided by the MacEwan University [Faculty of Arts and Science](https://www.macewan.ca/wcm/SchoolsFaculties/ArtsScience/AcademicPlanning/index.htm).

## Contact

Created by Ron Dyck and Nicholas M. Boers at [MacEwan University](https://www.macewan.ca/ComputerScience).

## License

This project is licensed under the MIT License.

We are actively developing this library, and we welcome all pull requests.
