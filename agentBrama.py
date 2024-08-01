import os
import re
import requests
import json
import base64
import anthropic
import langchain_anthropic
import base64
import io
from PIL import Image
from langchain_core.messages import HumanMessage
from langchain_anthropic import ChatAnthropic, Anthropic
from langchain.agents import create_react_agent, AgentExecutor
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.schema.runnable import RunnableLambda, RunnablePassthrough
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.tools import Tool
from langchain.agents import initialize_agent, AgentType
from checkDMARC import *
from braveSearch import *
from educationalModuleRAG import *

requests.packages.urllib3.disable_warnings()
BRAVE_API_KEY=os.environ.get('BRAVE_API_KEY')

anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY')
voyage_api_key = os.environ.get('VOYAGE_API_KEY')
umbrella_api_client = os.environ.get('UMBRELLA_API_CLIENT')
umbrella_api_secret = os.environ.get('UMBRELLA_API_SECRET')

if not BRAVE_API_KEY or not voyage_api_key or not voyage_api_key:
    raise ValueError("API keys not found. Please set BRAVE_API_KEY, VOYAGE_API_KEY, and ANTHROPIC_API_KEY environment variables.")


class CybersecurityAgent:
    def __init__(self):
        self.anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY')
        self.vt_api_key = os.environ.get('VT_API_KEY')

        if not self.anthropic_api_key or not self.vt_api_key or not BRAVE_API_KEY:
            raise ValueError("API keys not found. Please set ANTHROPIC_API_KEY and VT_API_KEY and BRAVE_API_KEY environment variables.")

        self.llm = ChatAnthropic(model="claude-3-5-sonnet-20240620", anthropic_api_key=self.anthropic_api_key)
        self.vision_llm = ChatAnthropic(model="claude-3-5-sonnet-20240620", anthropic_api_key=self.anthropic_api_key)
        self.setup_agent()


    def queryUrlHause(self, url):
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        data = {'url': url}
        response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data=data)
        json_response = response.json()
        if json_response['query_status'] == 'ok':
            return json.dumps(json_response, indent=4, sort_keys=False)
        elif json_response['query_status'] == 'no_results':
            url = 'http://' + url[8:]
            data = {'url': url}
            response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data=data)
            json_response = response.json()
            if json_response['query_status'] == 'ok':
                return json.dumps(json_response, indent=4, sort_keys=False)
            elif json_response['query_status'] == 'no_results':
                return "No results"
            else:
                return "Something went wrong"
        else:
            return "Something went wrong"


    def queryVirusTotal(self, url):
        VTapiEndpoint = "https://www.virustotal.com/api/v3/urls"
        payload = f'url={url}'
        headers = {
            'x-apikey': self.vt_api_key,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post(VTapiEndpoint, headers=headers, data=payload)
        try:
            VTurlID = response.json()["data"]["links"]["self"]
            response = requests.request("GET", VTurlID, headers=headers)
            return response.text
        except KeyError:
            return "Error: Invalid response data from VirusTotal API"

    def getDomainsRiskScore(self, url):

        api_url = "https://api.umbrella.com/auth/v2/token"

        usrAPIClientSecret = umbrella_api_client + ":" + umbrella_api_secret
        basicUmbrella = base64.b64encode(usrAPIClientSecret.encode()).decode()
        HTTP_Request_header = {"Authorization": "Basic %s" % basicUmbrella,
                                "Content-Type": "application/json;"}

        payload = json.dumps({
        "grant_type": "client_credentials"
        })

        response = requests.request("GET", api_url, headers=HTTP_Request_header, data=payload)
        print(response)

        try:
            accessToken = response.json()['access_token']

        except KeyError:
            return "Error: Invalid response data from Umbrella; check your API credential"
        

        api_url = "https://api.umbrella.com/investigate/v2/domains/risk-score/{}".format(url)

        payload = {}
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + accessToken
        }
        response = requests.request("GET", api_url, headers=headers, data=payload)

        json_data = response.json()

        return {"domain": url, "risk_score": json_data["risk_score"]}
    

    def analyze_domain(self, url):
        vt_data = self.queryVirusTotal(url)
        if vt_data.startswith("Error:"):
            return vt_data
        urlhaus_data = self.queryUrlHause(url)
        umbrella_data = self.getDomainsRiskScore(url)
        print(umbrella_data)

        template = """
        Analyze the following JSON data from two domain scan sources:
        VirusTotal scan: {JSON_DATA_Virus_Total}
        URLhaus scan: {JSON_DATA_URL_HOUSE}
        Umbrella scan: {JSON_DATA_Umbrella}

        Based on the analysis, generate a brief assessment following these rules:
        1. Start with "Based on related databases, domain identified as [malicious/suspicious/secure]"
        2. Use "malicious" if VirusTotal malicious count > 0 or URLhaus query_status is "ok"
        3. Use "suspicious" if VirusTotal suspicious count > 0 or undetected count is high
        4. Use "secure" if VirusTotal harmless count is high and malicious/suspicious counts are 0, and URLhaus query_status is "no_results"
        5. Highlight the URL status as online/offline/unknown from URLhaus data
        6. Check the blacklists key in URLhaus data and highlight if the domain is identified as a spammer domain, phishing domain, botnet C&C domain, compromised website, or not listed
        7. Check Umbrella scan data. The domain is malicious if the domain risk_score value is close to 100. Domains with risk_score values from 0 to 40 are safe.
        8. Provide a short summary of up to 10 words
        9. Add a brief description if needed, focusing on key findings

        Output the assessment in a concise paragraph.
        """
        prompt = PromptTemplate(template=template, input_variables=["JSON_DATA_Virus_Total", "JSON_DATA_URL_HOUSE", "JSON_DATA_Umbrella"])
        chain = prompt | self.llm | RunnableLambda(lambda x: x.content)
        return chain.invoke({"JSON_DATA_Virus_Total": vt_data, "JSON_DATA_URL_HOUSE": urlhaus_data, "JSON_DATA_Umbrella": umbrella_data})

    def describe_image(self, image_path):
        with Image.open(image_path) as img:
            img = img.convert('RGB')
            img_data = io.BytesIO()
            img.save(img_data, format='JPEG')
            img_data.seek(0)
            image_data = base64.b64encode(img_data.read()).decode('utf-8')

        model = ChatAnthropic(model="claude-3-5-sonnet-20240620", anthropic_api_key=self.anthropic_api_key)
        IMAGE_DESCRIPTION_PROMPT = """
        Analyze the following image in detail:

        1. Describe the overall layout and visual elements of the image.

        2. Extract and list ALL text visible in the image, exactly as it appears. Do not paraphrase or summarize. Include:
           - Headings
           - Body text
           - Labels
           - Buttons
           - Any other visible text

        3. Identify and list any of the following types of information, if present:
           - Email addresses
           - Phone numbers
           - Web domains
           - IP addresses
           - Social media handles
           - Names of people or organizations
           - Dates
           - Locations

        4. Note any logos, icons, or distinctive visual elements.

        5. Describe any charts, graphs, or data visualizations, if present.

        6. Mention any notable color schemes or design elements.

        7. If the image appears to be a screenshot of a specific type of content (e.g., email, social media post, web page), identify it.

        Please be as thorough and precise as possible in your analysis, ensuring that all text is captured exactly as it appears in the image.
        """
        message = HumanMessage(
            content=[
                {"type": "text", "text": IMAGE_DESCRIPTION_PROMPT},
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/jpeg",
                        "data": image_data,
                    },
                },
            ],
        )
        response = model.invoke([message])
        return response.content

    def setup_agent(self):
        tools = [
            Tool(
                name="Domain Analyzer",
                func=self.analyze_domain,
                description="Analyzes a domain or URL for potential security threats"
            ),
            Tool(
                name="Message Analyzer",
                func=self.analyze_message,
                description="Analyzes a message for phishing attempts"
            ),
            Tool(
                name="Phone Number Analyzer",
                func=self.analyze_phone,
                description="Analyzes a phone number for potential threats"
            )
        ]
        self.agent = initialize_agent(tools, self.llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, verbose=True)

    def analyze_phone(self, phone_number):

        phoneNumberVariants = generate_phone_number_variants(phone_number)
        searchData = checkPhoneLogic(phoneNumberVariants)

        template = """{Search_Data_Brave} \n\nPlease answer the user's question using only information from the search results. Include links to the relevant search result URLs within your answer. Keep your answer concise.

        User's question: Can you identify whether telephone number variants contains in this list {Phone_Number_Variants} is used for scams, phishing, or other suspicious activities? Highlight if the number is unsafe or write that there needs to be more information or if negative reviews and comments were not recorded in the first ten search results sites. 

        Assistant:
        """
        prompt = PromptTemplate(template=template, input_variables=["Search_Data_Brave", "Phone_Number_Variants"])
        chain = prompt | self.llm | RunnableLambda(lambda x: x.content)
        return chain.invoke({"Search_Data_Brave": searchData, "Phone_Number_Variants": phoneNumberVariants})
    
    

    def analyze_message(self, message):
        template = """
        Analyze the following message for potential phishing attempts:
        Message: {message}

        Provide your analysis, highlighting any suspicious elements:
        If message contains domain or email than also call Domain Analyzer tool, if contains phone number than call Phone Number Analyzer Tool
        """
        prompt = PromptTemplate(template=template, input_variables=["message"])
        chain = prompt | self.llm | RunnableLambda(lambda x: x.content)
        return chain.invoke({"message": message})

    def run(self):
        while True:
            user_input = input("Hi, this is an AI Agent Brama, who can help you check the security metrics and safety of the following resources: \nText messages, Site URL, Email, Phone number, and SMS. You can also use the educational mode to learn more about social engineering and cybersecurity threats, such as scams and phishing.\n\nEnter a URL, message, or write 'img', 'screenshot', or 'image' to attach an image, or 'education_mode' or 'quit' to exit: ")
            if user_input.lower() == 'quit':
                break

            # Check if user wants to attach a text file
            if user_input.lower() == 'file':
                file_path = input("Enter the path to the text file: ")
                with open(file_path, 'r') as file:
                    user_input = file.read()

            elif user_input.lower() == 'education_mode':
                educational_mode()
                continue

            # Extract domain from email address in user input
            email_match = re.search(r'\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b', user_input)
            if email_match:
                domain = email_match.group(1)
                domain_analysis = self.analyze_domain(domain)
                dmarc_analysis = checkDMARC(domain)
                user_input += f"\n\nDMARC analysis: {dmarc_analysis}"
            
            # Extract domain from user input
            domain_match = re.search(r'([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})', user_input)
            if domain_match:
                domain = domain_match.group(1)
                if 'Domain Analyzer' in [tool.name for tool in self.agent.tools]:
                    domain_analysis = self.agent.run(f"Analyze the domain: {domain}")
                    user_input += f"\n\nDomain analysis: {domain_analysis}"

            # Extract phone number from user input
            phone_match = re.search(r'\+?\d[\d -]{8,15}\d', user_input)
            
            if phone_match:
                phone_number = phone_match.group(0)
                phone_analysis = self.analyze_phone(phone_number)
                user_input += f"\n\nPhone analysis: {phone_analysis}"

            # Check if user wants to attach a screenshot
            if 'img' in user_input.lower() or 'screenshot' in user_input.lower() or 'image' in user_input.lower():
                image_path = input("Enter the path to the image: ")
                image_analysis = self.describe_image(image_path)
                user_input += f"\n\nImage analysis: {image_analysis}"

            response = self.agent.run(user_input)
            

            # Analyze message content
            message_analysis = self.analyze_message(response)
            print(f"Message analysis: {message_analysis}")

if __name__ == "__main__":
    try:
        agent = CybersecurityAgent()
        agent.run()
    except ValueError as e:
        print(f"Error: {e}")
