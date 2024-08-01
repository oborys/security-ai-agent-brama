from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import CharacterTextSplitter
from langchain_voyageai.embeddings import VoyageAIEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_anthropic import ChatAnthropic
from langchain.chains import RetrievalQA
import os
import random
from termcolor import colored
import urllib3

import warnings

# Filter out all LangChain deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="langchain")
warnings.filterwarnings("ignore", category=urllib3.exceptions.NotOpenSSLWarning)

anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY')
voyage_api_key = os.environ.get('VOYAGE_API_KEY')


QUESTIONS = [
    "How has vishing (voice phishing) changed since 2016 according to the text?",
    "Why is phishing considered the most dangerous of the four main social engineering vectors?",
    "What is meant by a 'combo attack' in social engineering?",
    "How can security experts use patterns in social engineering attacks to their advantage?",
    "What role does OSINT play in vishing attacks?",
    "What is spear phishing and how does it differ from regular phishing?",
    "How can penetration testers use phishing in their assessments?",
    "What is SMiShing and how does it relate to social engineering?",
    "What are some key elements to include in a social engineering penetration test report?",
    "How can organizations use educational phishing to improve security?",
    "What is credential harvesting in the context of vishing attacks?",
    "How can vishing be used to achieve full compromise of a target?",
    "What is the importance of sanitization in impersonation attacks?",
    "How does oxytocin relate to trust in social engineering scenarios?",
    "What role do observational skills play in social engineering reconnaissance?",
    "How can social engineers use metadata in their attacks?",
    "What is dOxing and how is it used in technical information gathering?",
    "How can webcams be exploited for social engineering purposes?",
    "What is pretexting and how is it used in social engineering?",
    "How do social engineers use Google for information gathering?",
    "What are some key elements to observe when conducting physical reconnaissance?",
    "How can social media be leveraged for social engineering attacks?",
    "What is the SE Framework mentioned in the context of penetration testing?",
    "How can word usage impact the success of a vishing attack?",
    "What is the M.A.P.P. approach to policy development for countering social engineering?",
    "How does the author address concerns about 'arming the bad guys' with social engineering knowledge?",
    "What is the importance of balancing attack and defense knowledge in social engineering?"
]

random.shuffle(QUESTIONS)

book_questions = QUESTIONS

def get_feedback(answer_type):
    responses = {
        "incorrect": [
            "Not quite. Let's try again!",
            "Oops! That's not right. Want to give it another shot?",
            "Incorrect. Don't worry, learning takes practice!"
        ],
        "correct": [
            "Excellent! You got it right.",
            "Perfect! Great job.",
            "Spot on! You're making great progress."
        ],
        "close": [
            "You're on the right track! Just a small adjustment needed.",
            "Almost there! Can you think of what might make this answer even better?",
            "Very close! You've got the main idea, but there's a small detail missing."
        ]
    }
    return random.choice(responses[answer_type])

# Educational mode
def educational_mode():
    # # Load the book data DB already exist
    # loader = PyPDFLoader("path_to_the_book")
    # documents = loader.load()
    
    # # Split the documents into chunks
    # text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    # documents = text_splitter.split_documents(documents)
    # print(len(documents))

    # Create embeddings for the chunks
    #embeddings = VoyageAIEmbeddings(voyage_api_key=voyage_api_key, model="voyage-large-2", batch_size=len(documents))
    embeddings = VoyageAIEmbeddings(voyage_api_key=voyage_api_key, model="voyage-large-2", batch_size=309)
    vectorstore = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)

    # # Check if the chroma_db directory exists
    # if os.path.exists("./chroma_db"):
    #     # Load the database from disk
    #     vectorstore = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)
    # else:
    #     # Create the database and persist it to disk
    #     vectorstore = Chroma.from_documents(documents, embeddings, persist_directory="./chroma_db")

    # if len(documents) == len(vectorstore.get()["documents"]):
    #     print("All content was loaded into the database.")
    # else:
    #     print("Not all content was loaded into the database.")

    # Define the language model
    llm = ChatAnthropic(model="claude-3-5-sonnet-20240620", anthropic_api_key=anthropic_api_key)

    # Define the retrieval-augmented generation chain
    qa = RetrievalQA.from_chain_type(llm=llm, chain_type="stuff", retriever=vectorstore.as_retriever())


    print(colored("Welcome to educational mode. Please answer the following questions. If you don’t know, tell this as an answer (for example, type “I don’t know”), and then the assistant provides you with helpful information. Enjoy your education.", "green"))
    for i, question in enumerate(QUESTIONS):
        print(f"Question {i+1}: {question}")
        response = qa.run(question)
        user_answer = input("Your answer: ")
        
        comparison_prompt_feedback = f"Compare the following two answers to the question '{question}':\nUser Answer: {user_answer}\nAI assistant answer: {response}\nDescribe what is in the AI assistant answer and suggest how the User Answer can be improved to be more accurate and detailed."
        comparison_response = llm.invoke(comparison_prompt_feedback)
        
        clean_response = comparison_response.content if hasattr(comparison_response, 'content') else str(comparison_response)
        clean_response = clean_response.replace("content='", "").rstrip("'")
        
        context_response = f"Here's a suggestion for improving your answer:\n{clean_response}\n\nThe correct answer is:\n{response}"
        
        if "User Answer" in clean_response:
            feedback = get_feedback("correct")
        elif "AI assistant answer" in clean_response:
            feedback = get_feedback("incorrect")
        else:
            feedback = get_feedback("close")
        
        print(feedback)
        print(context_response)
