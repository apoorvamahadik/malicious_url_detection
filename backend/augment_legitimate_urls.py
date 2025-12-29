"""
Script to augment the dataset with more legitimate URL examples
This helps the model learn what legitimate domains look like
"""
import pandas as pd
import os

# Comprehensive list of legitimate domains
LEGITIMATE_DOMAINS = [
    # Search & Tech Giants
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com', 'netflix.com',
    
    # Developer & Tech
    'github.com', 'stackoverflow.com', 'gitlab.com', 'bitbucket.org', 
    'npmjs.com', 'pypi.org', 'docker.com', 'kubernetes.io', 'cloudflare.com',
    
    # Media & News
    'cnn.com', 'bbc.com', 'nytimes.com', 'reuters.com', 'theguardian.com',
    'washingtonpost.com', 'forbes.com', 'bloomberg.com', 'techcrunch.com',
    
    # Education & Knowledge
    'wikipedia.org', 'medium.com', 'quora.com', 'stackoverflow.com', 
    'khanacademy.org', 'coursera.org', 'edx.org', 'udemy.com',
    
    # E-commerce & Services
    'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com', 'etsy.com',
    'shopify.com', 'aliexpress.com', 'booking.com', 'airbnb.com',
    
    # Social & Community
    'reddit.com', 'pinterest.com', 'tumblr.com', 'discord.com', 'slack.com',
    'whatsapp.com', 'telegram.org', 'zoom.us', 'teams.microsoft.com',
    
    # Financial (legitimate)
    'paypal.com', 'stripe.com', 'square.com', 'chase.com', 'bankofamerica.com',
    'wellsfargo.com', 'citibank.com', 'americanexpress.com',
    
    # Content & Entertainment
    'spotify.com', 'twitch.tv', 'vimeo.com', 'soundcloud.com', 'hulu.com',
    'disneyplus.com', 'hbomax.com', 'primevideo.com',
    
    # Productivity
    'dropbox.com', 'drive.google.com', 'onedrive.com', 'notion.so',
    'trello.com', 'asana.com', 'monday.com', 'airtable.com',
    
    # Design & Creative
    'adobe.com', 'canva.com', 'figma.com', 'dribbble.com', 'behance.net',
    
    # Government & Organizations
    'gov.uk', 'usa.gov', 'europa.eu', 'who.int', 'un.org',
    
    # Domain registrars & hosting
    'godaddy.com', 'namecheap.com', 'bluehost.com', 'hostgator.com',
    
    # Universities (examples)
    'mit.edu', 'stanford.edu', 'harvard.edu', 'berkeley.edu', 'ox.ac.uk',
    
    # Other popular
    'wordpress.com', 'blogger.com', 'wix.com', 'squarespace.com',
    'mailchimp.com', 'surveymonkey.com', 'typeform.com'
]

def generate_url_variants(domain):
    """Generate various URL patterns for a domain"""
    variants = []
    
    # Different protocols and www
    prefixes = ['https://www.', 'https://', 'http://www.', 'http://']
    
    # Different path patterns
    paths = [
        '',
        '/index.html',
        '/home',
        '/about',
        '/contact',
        '/products',
        '/services',
        '/blog',
        '/search?q=example',
        '/user/profile',
        '/account/settings',
        '/page/123',
        '/category/tech',
        '/help',
        '/support',
        '/docs',
        '/api/v1/endpoint',
        '/download',
        '/pricing',
        '/features'
    ]
    
    for prefix in prefixes:
        for path in paths:
            url = f"{prefix}{domain}{path}"
            variants.append(url)
    
    return variants

def create_augmented_dataset():
    """Create an augmented dataset with legitimate URLs"""
    print("=" * 60)
    print("AUGMENTING DATASET WITH LEGITIMATE URLs")
    print("=" * 60)
    
    # Load original dataset
    possible_paths = [
        "data/malicious_phish.csv",
        "../data/malicious_phish.csv",
        "malicious_phish.csv"
    ]
    
    original_df = None
    for path in possible_paths:
        if os.path.exists(path):
            print(f"\nLoading original dataset from: {path}")
            original_df = pd.read_csv(path)
            break
    
    if original_df is None:
        print("ERROR: Could not find original dataset!")
        return
    
    print(f"Original dataset: {len(original_df)} URLs")
    
    # Prepare original data
    if 'type' in original_df.columns:
        original_df = original_df.rename(columns={'type': 'label'})
    elif len(original_df.columns) == 2:
        original_df.columns = ['url', 'label']
    
    print("\nOriginal distribution:")
    print(original_df['label'].value_counts())
    
    # Generate legitimate URL examples
    print(f"\nGenerating variants for {len(LEGITIMATE_DOMAINS)} legitimate domains...")
    
    legitimate_urls = []
    for domain in LEGITIMATE_DOMAINS:
        variants = generate_url_variants(domain)
        for url in variants:
            legitimate_urls.append({'url': url, 'label': 'benign'})
    
    legit_df = pd.DataFrame(legitimate_urls)
    print(f"Generated {len(legit_df)} legitimate URL examples")
    
    # Combine datasets
    print("\nCombining datasets...")
    augmented_df = pd.concat([original_df, legit_df], ignore_index=True)
    
    print(f"\nAugmented dataset: {len(augmented_df)} URLs")
    print("\nNew distribution:")
    print(augmented_df['label'].value_counts())
    
    # Save augmented dataset
    output_path = "data/malicious_phish_augmented.csv"
    if not os.path.exists("data"):
        os.makedirs("data")
    
    augmented_df.to_csv(output_path, index=False)
    print(f"\n✓ Augmented dataset saved to: {output_path}")
    
    print("\n" + "=" * 60)
    print("AUGMENTATION COMPLETE!")
    print("=" * 60)
    print("\nTo use this augmented dataset:")
    print("1. Update model.py to load 'malicious_phish_augmented.csv'")
    print("2. OR rename it to 'malicious_phish.csv' (backup original first)")
    print("3. Delete old model files: model.pkl, vectorizer.pkl, label_encoder.pkl")
    print("4. Run: python train_model.py")

if __name__ == '__main__':
    create_augmented_dataset()