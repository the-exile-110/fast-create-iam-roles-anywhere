package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/manifoldco/promptui"
	"os"
	"os/exec"
)

type CaData struct {
	HostName string
	Country  string
	State    string
	Locality string
	Org      string
	OrgUnit  string
}

type TrustAnchorOutput struct {
	TrustAnchor struct {
		TrustAnchorArn string `json:"trustAnchorArn"`
	} `json:"trustAnchor"`
}

type RoleOutput struct {
	Role struct {
		Arn string `json:"Arn"`
	} `json:"Role"`
}

type ProfileOutput struct {
	Profile struct {
		ProfileArn string `json:"profileArn"`
	} `json:"profile"`
}

func checkTools(tools []string) []string {
	var notInstalled []string
	for _, tool := range tools {
		cmd := exec.Command("which", tool)
		_, err := cmd.Output()
		if err != nil {
			notInstalled = append(notInstalled, tool)
		}
	}
	return notInstalled
}

func createCA() (*CaData, error) {
	prompt := promptui.Prompt{
		Label: "Enter your Hostname: (e.g. example.com)",
	}
	hostName, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	prompt = promptui.Prompt{
		Label: "Enter your Country: (e.g. JP)",
	}
	country, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	prompt = promptui.Prompt{
		Label: "Enter your State: (e.g. Tokyo)",
	}
	state, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	prompt = promptui.Prompt{
		Label: "Enter your Locality: (e.g. Shibuya-ku)",
	}
	locality, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	prompt = promptui.Prompt{
		Label: "Enter your Organization: (e.g. Example)",
	}
	organization, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	prompt = promptui.Prompt{
		Label: "Enter your OrganizationalUnit: (e.g. Example)",
	}
	organizationalUnit, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	caJson := map[string]interface{}{
		"hosts": []string{
			hostName,
		},
		"key": map[string]interface{}{
			"algo": "rsa",
			"size": 2048,
		},
		"names": []map[string]interface{}{
			{
				"C":  country,
				"ST": state,
				"L":  locality,
				"O":  organization,
				"OU": organizationalUnit,
			},
		},
	}

	caJsonBytes, err := json.Marshal(caJson)
	if err != nil {
		return nil, err
	}

	f, err := os.Create("ca.json")
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(f)

	_, err = f.Write(caJsonBytes)
	if err != nil {
		return nil, err
	}

	caData := CaData{
		HostName: hostName,
		Country:  country,
		State:    state,
		Locality: locality,
		Org:      organization,
		OrgUnit:  organizationalUnit,
	}

	return &caData, nil
}

func createCAFiles() error {
	cmd := "cfssl gencert -initca ca.json | cfssljson -bare ca"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return err
	}
	fmt.Println(string(out))

	return nil
}

func createTrustAnchor(trustAnchorName string) (string, error) {

	file, err := os.Open("ca.pem")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return "", err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	var caData string
	for scanner.Scan() {
		caData += scanner.Text() + "\n"
	}

	cmd := fmt.Sprintf("aws rolesanywhere create-trust-anchor --enabled --name %s --source \"sourceData={x509CertificateData=%s},sourceType=CERTIFICATE_BUNDLE\"", trustAnchorName, string(caData))
	out, err := exec.Command("bash", "-c", cmd).Output()
	fmt.Println(cmd)
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}

	var trustAnchorOutput TrustAnchorOutput
	err = json.Unmarshal(out, &trustAnchorOutput)
	if err != nil {
		return "", err
	}

	trustAnchorArn := trustAnchorOutput.TrustAnchor.TrustAnchorArn
	return trustAnchorArn, nil
}

func createIamRole(roleName string, ou string) (string, error) {
	policyJson := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Principal": map[string]interface{}{
					"Service": "rolesanywhere.amazonaws.com",
				},
				"Action": []string{
					"sts:AssumeRole",
					"sts:TagSession",
					"sts:SetSourceIdentity",
				},
				"Condition": map[string]interface{}{
					"StringEquals": map[string]interface{}{
						"aws:PrincipalTag/x509Subject/OU": ou,
					},
				},
			},
		},
	}
	policyJsonBytes, err := json.Marshal(policyJson)
	if err != nil {
		return "", err
	}

	f, err := os.Create("role-policy.json")
	if err != nil {
		return "", err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(f)

	_, err = f.Write(policyJsonBytes)
	if err != nil {
		return "", err
	}

	cmd := exec.Command("aws", "iam", "create-role", "--role-name", roleName, "--assume-role-policy-document", "file://role-policy.json")
	fmt.Println(cmd.String())
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	fmt.Println(string(out))

	var roleOutput RoleOutput
	err = json.Unmarshal(out, &roleOutput)
	if err != nil {
		return "", err
	}

	roleArn := roleOutput.Role.Arn

	return roleArn, nil
}

func createRolesAnywhereProfile(profileName string, roleArn string) (string, error) {
	cmd := exec.Command("aws", "rolesanywhere", "create-profile", "--name", profileName, "--role-arns", roleArn, "--enabled", "true")
	fmt.Println(cmd.String())
	out, err := cmd.Output()

	if err != nil {
		return "", err
	}
	fmt.Println(string(out))

	var profileOutput ProfileOutput
	err = json.Unmarshal(out, &profileOutput)
	if err != nil {
		return "", err
	}

	profileArn := profileOutput.Profile.ProfileArn
	return profileArn, nil
}

func createCSR(hostName string, data CaData) error {
	csrJson := map[string]interface{}{
		"CN": hostName,
		"names": []map[string]interface{}{
			{
				"C":  data.Country,
				"ST": data.State,
				"L":  data.Locality,
				"O":  data.Org,
				"OU": data.OrgUnit,
			},
		},
	}

	csrJsonBytes, err := json.Marshal(csrJson)
	if err != nil {
		return err
	}

	f, err := os.Create("csr.json")
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(f)

	_, err = f.Write(csrJsonBytes)
	if err != nil {
		return err
	}

	cmd := "cfssl gencert -ca ca.pem -ca-key ca-key.pem csr.json| cfssljson -bare " + hostName
	fmt.Println(cmd)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return err
	}
	fmt.Println(string(out))

	return nil
}

func main() {
	// check brew, cfssl, jq, awscli
	fmt.Println("Checking tools...")
	notInstalled := checkTools([]string{"cfssl", "jq", "aws", "aws_signing_helper"})
	if len(notInstalled) > 0 {
		fmt.Println("The following tools are not installed:")
		for _, tool := range notInstalled {
			fmt.Println(tool)
		}
	} else {
		fmt.Println("All tools are installed.")
	}

	// create ca.json. need input: Hostname, Country, State, Locality, Organization, OrganizationalUnit
	fmt.Println("Creating ca.json...")
	caData, err := createCA()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(caData)

	// use `cfssl gencert -initca ca.json | cfssljson -bare ca` to create ca.pem, ca-key.pem
	fmt.Println("Creating ca.pem, ca-key.pem...")
	if err := createCAFiles(); err != nil {
		fmt.Println(err)
	}

	// use `aws rolesanywhere create-trust-anchor` to create trust anchor. need input: trust anchor name
	prompt := promptui.Prompt{
		Label: "Enter your Trust Anchor Name: (e.g. example-trust-anchor)",
	}
	trustAnchorName, err := prompt.Run()
	if err != nil {
		fmt.Println(err)
	}

	trustAnchorArn, err := createTrustAnchor(trustAnchorName)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Trust anchor created: " + trustAnchorArn)

	// use `aws iam create-role` to create role and add inline policy. need input: role name
	prompt = promptui.Prompt{
		Label: "Enter your Role Name: (e.g. example-role)",
	}
	roleName, err := prompt.Run()
	roleArn, err := createIamRole(roleName, caData.OrgUnit)
	if err != nil {
		fmt.Println(err)
	}

	// use `aws rolesanywhere create-profile` to create profile. need input: profile name
	prompt = promptui.Prompt{
		Label: "Enter your Profile Name: (e.g. example-profile)",
	}
	profileName, err := prompt.Run()
	profileArn, err := createRolesAnywhereProfile(profileName, roleArn)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Profile created: " + profileArn)

	// create csr.json. need input: CSR Hostname
	prompt = promptui.Prompt{
		Label: "Enter your CSR Hostname: (e.g. example.com)",
	}
	csrHostname, err := prompt.Run()
	fmt.Println("Creating csr.json...")
	if err := createCSR(csrHostname, *caData); err != nil {
		fmt.Println(err)
	}

	// success, and out put the use case
	useCase := `
    Success! Please follow the steps below to use the certificate:

	output=$(aws_signing_helper credential-process \
                     --certificate %s.pem \
                     --private-key %s-key.pem \
                     --trust-anchor-arn %s \
                     --profile-arn %s \
                     --role-arn %s)

	export AWS_ACCESS_KEY_ID=$(echo $output | jq -r '.AccessKeyId')
	export AWS_SECRET_ACCESS_KEY=$(echo $output | jq -r '.SecretAccessKey')
	export AWS_SESSION_TOKEN=$(echo $output | jq -r '.SessionToken')    
    `
	fmt.Printf(useCase, csrHostname, csrHostname, trustAnchorArn, profileArn, roleArn)
}
