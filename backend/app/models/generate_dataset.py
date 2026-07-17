# LOCATION: backend/ml_models/generate_dataset.py
"""
Generates a rich, diverse synthetic threat dataset.
Goal: ~2000+ samples with genuinely distinct phrasing per category,
including indirect/colloquial language that wraps real threat intent.
Run standalone: python ml_models/generate_dataset.py
"""

import json
import random
from pathlib import Path

OUTPUT_PATH = Path(__file__).parent / "training_data.json"

# ─────────────────────────────────────────────────────────────────────────────
# SAFE emails — diverse, realistic, no threat content
# ─────────────────────────────────────────────────────────────────────────────
SAFE = [
    # Work / business
    "Hi, just wanted to follow up on the meeting scheduled for tomorrow.",
    "Please find the attached invoice for your review.",
    "The quarterly report is ready for your review.",
    "Can we reschedule our call to next week?",
    "Here are the minutes from yesterday's team meeting.",
    "The project deadline has been extended to next Friday.",
    "Please complete the employee satisfaction survey by end of week.",
    "The annual performance review cycle begins next month.",
    "Please update your contact information in the HR portal.",
    "The new software update includes several bug fixes.",
    "Please submit your timesheet by Friday 5 PM.",
    "Heads up — the server maintenance window is tonight from 2–4 AM.",
    "Just a reminder to submit your expense reports before month end.",
    "The conference room is booked for Thursday 2–3 PM.",
    "We need to align on the Q3 roadmap before the board meeting.",
    "Can you send over the latest deck? I need it for the client call.",
    "Your access to the dev environment has been provisioned.",
    "The new HR policy takes effect on the 1st — please read it.",
    "We're moving the stand-up to 9:30 starting Monday.",
    "Your VPN credentials have been reset, see attachment.",
    "Friendly reminder that the company all-hands is this Friday.",
    "I'll be OOO next week, please reach out to Sarah in my absence.",
    "Please review and sign the NDA before the kickoff call.",
    "The vendor proposal looks solid — let's discuss tomorrow.",
    "Congrats on closing the deal! Great work by the whole team.",
    # Personal / social
    "Congratulations on your promotion! Well deserved.",
    "Happy birthday! Hope you have a wonderful day.",
    "Thanks for dinner last night, it was really lovely.",
    "Are you free Saturday? We're having a few people over.",
    "Just checking in — how are you doing after the move?",
    "We'd love to catch up sometime! It's been ages.",
    "The kids had so much fun at the party, thank you!",
    "See you at the reunion next month!",
    "Hope you're feeling better — let me know if you need anything.",
    "Quick question: do you have Marcus's new number?",
    # Transactional / notifications
    "Thank you for your order. It will ship within 2-3 business days.",
    "Reminder: your subscription renews on the 15th.",
    "Please review the attached contract and let me know your thoughts.",
    "Your password reset request has been received.",
    "Welcome to our newsletter! Here are this week's top stories.",
    "Your appointment is confirmed for Monday at 10 AM.",
    "Your flight has been confirmed. Check-in opens 24 hours before departure.",
    "Your bank statement for last month is now available.",
    "Thank you for attending our webinar. Here is the recording.",
    "Your package has been delivered to your front door.",
    "Your insurance claim has been processed successfully.",
    "Your tax documents are ready to download.",
    "We are pleased to inform you that your loan application was approved.",
    "Your account has been verified. Welcome aboard!",
    "Receipt for your recent purchase — thank you for shopping with us.",
    "Your return request has been approved. Refund in 5–7 days.",
    "Your streaming subscription has been renewed.",
    "Two-factor authentication has been enabled on your account.",
    "Your donation to the food bank has been received. Thank you.",
    "Shipping update: your parcel is out for delivery today.",
    # Community / admin
    "The office will be closed on public holidays.",
    "Join us for the company picnic this Saturday.",
    "The library book you requested is now available for pickup.",
    "The road closure on Main Street will end by Thursday.",
    "Please register for the upcoming fire drill on Wednesday.",
    "The parking garage will be closed for resurfacing this weekend.",
    "Voter registration closes in two weeks — make sure you're registered.",
    "The neighborhood association meeting is Thursday at 7 PM.",
    "School will be closed Friday for teacher professional development.",
    "The water will be shut off briefly Tuesday morning for maintenance.",
    # Aggressive-sounding but benign (hard negatives — should NOT be flagged)
    "I'm going to destroy you at tennis on Saturday.",
    "We absolutely killed it in the pitch meeting today!",
    "My boss is going to kill me if I miss another deadline.",
    "I will literally die if they cancel this show.",
    "The competition is going to tear us apart if we don't step it up.",
    "You need to crush this presentation — the board expects a lot.",
    "I'm dead tired, can we reschedule to tomorrow?",
    "If this deal falls through I'm going to lose my mind.",
    "We smashed our sales targets this quarter!",
    "This codebase is a nightmare — someone should put it out of its misery.",
    "Our CEO is on the warpath about the missed deadline.",
    "I'll strangle whoever keeps leaving dirty dishes in the break room.",
    "That game was brutal — they massacred us.",
    "Kill the Jenkins build and start fresh.",
    "We need to shoot down this proposal before it goes any further.",
]

# ─────────────────────────────────────────────────────────────────────────────
# BOMB THREATS — direct and indirect
# ─────────────────────────────────────────────────────────────────────────────
BOMB_THREAT = [
    # Direct / explicit
    "There is a bomb planted in the building. Evacuate immediately.",
    "We have placed explosives in the terminal. You have one hour.",
    "A bomb will detonate at noon unless our demands are met.",
    "Explosives have been planted throughout the airport. Leave now.",
    "The device is set to explode at midnight. Evacuate the area.",
    "We planted a pipe bomb in your office. Pay us or it goes off.",
    "There is an IED hidden in the parking lot. Evacuate now.",
    "A car bomb has been placed near the main entrance.",
    "The timer is counting down. The bomb will detonate in 30 minutes.",
    "We have rigged the building with explosives. This is your only warning.",
    "Bomb threat: evacuate the courthouse immediately, device located inside.",
    "Your school has been rigged with explosives. Students must leave now.",
    "We planted dynamite in the subway station. Explosion imminent.",
    "A suicide bomber is inside the shopping mall right now.",
    "The bridge has been rigged to explode. Do not use it.",
    "We have placed C4 explosives throughout the stadium.",
    "Detonation will occur at 3 PM unless demands are fulfilled.",
    "Multiple bombs have been planted across the city center.",
    "The bomb is inside the government building. Evacuate immediately.",
    "We will detonate the device if our demands are not met in 2 hours.",
    # Oblique / indirect phrasing
    "There's a package under the main stairwell you really don't want to ignore.",
    "Something I left in the lobby is going to make a very loud noise at 2 PM.",
    "I'd evacuate that building if I were you. Something's ticking in there.",
    "That thing I left in the parking garage — I wouldn't stand near it.",
    "You might want to clear the building. I left a surprise for everyone.",
    "The device I installed yesterday has a timer. You have until noon.",
    "I hope everyone got out of the arena. My gift to them arrives at 6.",
    "There's a reason I've been avoiding the east wing of your building.",
    "Let's just say the fire alarm going off tomorrow won't be a drill.",
    "I've been a bit busy wiring things up in your basement. You'll find out soon.",
    "The package I sent your office — please don't open it, just run.",
    "Someone left something in the food court that shouldn't be there. Tick tick.",
    "Your staff cafeteria has a problem that no fire extinguisher can fix.",
    "Don't go into work tomorrow. Trust me on this one.",
    "That unattended bag by gate 14 isn't lost luggage.",
    # Email-style
    "Dear facility manager, you should probably check under the conference tables.",
    "I'm writing to inform you that the device in your mailroom is active.",
    "FYI the east parking structure won't be standing much longer.",
    "To whom it may concern: please evacuate before the end of business today.",
    "I strongly advise clearing all personnel from the building right now.",
    # Coded / euphemistic
    "The fireworks show happens at noon whether or not you evacuate.",
    "My science project goes live in your cafeteria in forty minutes.",
    "The present I left you is ticking. You should probably open it quickly — outside.",
    "Let's see how your glass ceiling handles a little overpressure.",
    "The noise complaint you're about to get from your neighbors will be substantial.",
    # Mixed / escalating
    "Pay what you owe or the explosive I hid in the warehouse goes off tonight.",
    "Our demands are simple. Meet them or the device in locker 14 activates.",
    "This is your third and final warning. The bomb goes off at dawn.",
    "Tell your boss we're serious. There's a reason we've been watching the building.",
    "You laughed at our last message. The device in unit 3 isn't laughing.",
]

# ─────────────────────────────────────────────────────────────────────────────
# VIOLENCE THREATS — direct and oblique
# ─────────────────────────────────────────────────────────────────────────────
VIOLENCE = [
    # Direct
    "I will kill you if you don't comply with my demands.",
    "We are going to shoot everyone in that building tomorrow.",
    "You will not survive the week. I have a gun and I know where you live.",
    "I'm going to murder you and your entire family.",
    "There will be a mass shooting at the school on Monday.",
    "I will hunt you down and execute you in front of everyone.",
    "You are going to die for what you did. I am coming for you.",
    "We will slaughter everyone at the event. No one will be spared.",
    "I have a rifle and I am going to shoot you on sight.",
    "Blood will be shed at the courthouse tomorrow morning.",
    "I am planning to carry out a massacre at the university.",
    "You and your coworkers will be dead by Friday.",
    "I will stab you to death the next time I see you.",
    "We are armed and ready to attack your headquarters tonight.",
    "The carnage will begin at the opening ceremony.",
    "I will shoot you the moment you leave your house.",
    "Everyone at the conference will be killed. This is a warning.",
    "You will pay with your blood for betraying us.",
    "I have weapons and I am not afraid to use them on you.",
    "We plan to carry out a violent attack at the station this weekend.",
    # Colloquial / indirect
    "I know exactly where you park your car. You won't make it home.",
    "You really should update your will before next week.",
    "Say your goodbyes while you still can.",
    "I've been practicing my aim. You're going to see that up close.",
    "You've got maybe two days left if you keep this up.",
    "I'm done talking. Next time we meet, someone's leaving in a bag.",
    "You made a very serious mistake and you're going to feel it.",
    "I've thought about this a long time. I'm ready to do what needs to be done to you.",
    "People have disappeared for less than what you did to me.",
    "I've already picked the spot. You don't get to run this time.",
    "Enjoy the weekend because it might be your last.",
    "Next time I see you, I'm bringing more than words.",
    "You think I'm joking but I've already bought what I need.",
    "You should probably tell someone where you're going every day. For safety.",
    "The way I see it, you've got one option: leave the city now.",
    # Coded anger + intent
    "I've kept quiet long enough. Someone has to make this right and it's going to be me.",
    "You ruined my life so now I'm going to end yours.",
    "I've got nothing left to lose and you're going to find out what that means.",
    "You took everything from me. Fair is fair.",
    "You think you're untouchable. I'm going to prove you wrong, permanently.",
    # Workplace / targeted
    "When I get back into that office there are going to be consequences you can't imagine.",
    "You fired the wrong person. I'll make sure you regret that decision.",
    "Tell HR I said hi. Won't matter much after Monday.",
    "Keep ignoring my emails. We'll settle this in person.",
    "I know the layout of your building very well. See you soon.",
]

# ─────────────────────────────────────────────────────────────────────────────
# TERROR THREATS — direct and indirect
# ─────────────────────────────────────────────────────────────────────────────
TERROR = [
    # Direct
    "Our cell will launch a terror attack on the city center.",
    "The infidels will face jihad. The attack begins at dawn.",
    "We are planning a biological weapon attack on the water supply.",
    "The martyrs are ready to sacrifice themselves for the cause.",
    "We have obtained sarin gas and will release it in the subway.",
    "The dirty bomb is ready. The infidels will suffer.",
    "Our extremist group will attack the parliament building.",
    "Chemical weapons will be deployed in the crowded marketplace.",
    "The terrorist cell will strike at the airport departure lounge.",
    "We have anthrax and will mail it to government officials.",
    "The WMD attack will paralyze the entire city.",
    "Radicalized members of our group have infiltrated the facility.",
    "The nerve agent has been synthesized. The attack is imminent.",
    "Our militia will destroy the military base at 0200 hours.",
    "The insurgents are ready to strike the power grid.",
    "We are planning a coordinated attack using weapons of mass destruction.",
    "The caliphate demands surrender or face a terror campaign.",
    "Guerrilla forces will attack civilian infrastructure next week.",
    "Our holy war against the infidels begins with this attack.",
    # Indirect / coded
    "The operation goes live at the signal. Targets have been identified.",
    "The brothers are in position. The timeline has been moved up to Friday.",
    "Phase two of the operation will be larger than what happened last year.",
    "The sleeper assets have been activated. The event will not be stopped.",
    "We have identified multiple soft targets in the downtown corridor.",
    "The package containing the agent has been dispatched to three locations.",
    "Our operatives are in place. The western media won't know what hit them.",
    "By the grace of God, the infidels will finally understand our resolve.",
    "The martyrdom operation in the financial district is two weeks away.",
    "We have been preparing this for three years. The time is now.",
    "The contamination of the reservoir will begin after the supply inspection.",
    "Our brothers in the network are ready. All cells confirm readiness.",
    "The operation cannot be stopped. Too many people are involved now.",
    "We have the means and we have the will. The date is set.",
    "The coordinated strikes will bring the economy to its knees.",
    # Manifesto-style
    "This government will fall. We will not stop until our demands are met by force.",
    "The people have been oppressed too long. The uprising begins this week.",
    "No negotiation, no mercy. The attack will send a message no one can ignore.",
    "Death to the occupiers. Our fighters are prepared to die for the cause.",
    "The regime's days are numbered. We act for all those who suffered.",
]

# ─────────────────────────────────────────────────────────────────────────────
# EXTORTION — direct and indirect
# ─────────────────────────────────────────────────────────────────────────────
EXTORTION = [
    # Direct
    "Pay 5 bitcoin to this address or we will release your private photos.",
    "Transfer $10,000 or we will expose your secrets to the public.",
    "We have your data. Send cryptocurrency or everything gets leaked.",
    "Pay the ransom within 48 hours or your files will be deleted.",
    "We know what you did. Pay us or your family finds out.",
    "Send BTC to this wallet or we will release the video.",
    "Your company data has been encrypted. Pay to get it back.",
    "Wire transfer $50,000 by tomorrow or we release the information.",
    "We will blackmail you unless you transfer funds immediately.",
    "Pay up or face the consequences. This is your only warning.",
    "We have compromising evidence. Send money or it goes public.",
    "Your accounts have been hacked. Pay ransom to prevent exposure.",
    "Unless you pay $20,000 we will destroy your reputation.",
    "Time is running out. Send the cryptocurrency or suffer the consequences.",
    "We have been watching you. Pay or your secrets are revealed.",
    "Extortion notice: pay by midnight or face public humiliation.",
    "Your private communications have been intercepted. Pay us.",
    "If you don't transfer money we will contact your employer.",
    "We demand payment or your personal data will be sold.",
    "You have 24 hours to send bitcoin or we expose everything.",
    # Indirect / soft-coercive
    "I have some information about you that I'm sure you'd prefer stayed private.",
    "It would be a shame if certain people found out what you've been up to.",
    "I think we can come to a mutually beneficial arrangement, if you're interested.",
    "I've been holding onto this material for a while. I'd like to discuss terms.",
    "You might want to reach out to me before I reach out to your family.",
    "Let's keep this between us. I only need a small token of goodwill.",
    "I'm not a bad person. I just need you to make this worth my while.",
    "The thing about silence is that it has a price. I'm telling you that price.",
    "Some emails got forwarded to me accidentally. I think you know which ones.",
    "There's footage from that night that you wouldn't want circulating.",
    "Your business partners would find certain documents very interesting.",
    # Corporate / professional framing
    "I'd suggest settling this privately before it becomes a legal matter. Call me.",
    "Our organization has obtained internal documents from your company. Respond within 24 hours.",
    "This is a formal notice that sensitive records are in our possession.",
    "You have been identified as a target. Cooperation ensures confidentiality.",
    "We are prepared to auction the data unless a private arrangement is reached.",
    # Technical / ransomware tone
    "All files on your network have been encrypted with military-grade AES-256.",
    "Your backups have also been deleted. The only way to recover is to pay.",
    "The decryption key will be destroyed if we do not receive payment in 72 hours.",
    "We have exfiltrated 40GB of data before encrypting. Non-payment means publication.",
    "Your customer database is in our hands. The cost to keep it private is $100,000.",
]

# ─────────────────────────────────────────────────────────────────────────────
# HARASSMENT / STALKING — direct and indirect
# ─────────────────────────────────────────────────────────────────────────────
HARASSMENT = [
    # Direct
    "I know where you live and I am watching you every day.",
    "You cannot hide from me. I will find you wherever you go.",
    "I am following your children to school every morning.",
    "Your family is not safe. I am watching your house.",
    "You will regret what you did to me. I am coming for you.",
    "I know your daily schedule and where your kids go to school.",
    "You cannot escape me. Nowhere is safe for you.",
    "I have been stalking you for months and you haven't noticed.",
    "Your children are in danger if you don't do what I say.",
    "I will intimidate you until you comply with my demands.",
    "I am watching you right now through your window.",
    "You made a mistake crossing me. I will make you pay for this.",
    "Your family will suffer the consequences of your actions.",
    "I know your home address, your work address, and your car.",
    "You cannot get a restraining order that will stop me.",
    "I will bully you online and offline until you break.",
    "Everyone you love is being watched. Do what I say.",
    "You thought you were safe but I am right outside your door.",
    "I will make your life miserable until you give me what I want.",
    "Coming for you tonight. Make sure your doors are locked.",
    # Indirect / soft stalking
    "Nice haircut. I saw you at the salon on Thursday.",
    "That blue coat you wore yesterday looked really good on you.",
    "I saw you drop your kids off this morning. Cute kids.",
    "You didn't notice me at the coffee shop but I was there.",
    "Your morning run takes you right past the park every day. I know.",
    "I've been learning your routine. I know where you'll be tomorrow.",
    "How's your sister in Portland doing? She has a lovely garden.",
    "That's a nice apartment on the 4th floor. East-facing, right?",
    "You should really draw your blinds at night.",
    "I know which car is yours in the lot at work.",
    # Emotional coercion
    "You think you can just block me and move on? That's not how this works.",
    "I've sent this message from 12 different accounts and I'll keep going.",
    "Ignoring me just makes things worse. You know what I'm capable of.",
    "I will contact everyone you know if you don't respond to me.",
    "You owe me an explanation and I'm not going away until I get one.",
    "Every time you refuse to talk to me, the consequences get worse.",
    "I've already started sending things to people you know. It's not too late to stop me.",
    "Your silence is a choice that has costs. Think carefully.",
    "I've been patient but I'm running out of it. You need to respond.",
    "This ends when I decide it ends, not when you decide.",
]

# ─────────────────────────────────────────────────────────────────────────────
# SCHOOL THREATS — direct and indirect
# ─────────────────────────────────────────────────────────────────────────────
SCHOOL_THREAT = [
    # Direct
    "I am going to shoot up the school tomorrow morning.",
    "There will be a school shooting at Central High on Friday.",
    "Students at the university will die in the attack next week.",
    "I have weapons and I am planning a Columbine-style attack.",
    "The campus bomb will go off during the morning assembly.",
    "All students in the classroom will be killed at 9 AM.",
    "I have a gun and I am bringing it to school tomorrow.",
    "The school attack has been planned for months. No one can stop it.",
    "We will carry out a mass shooting at the college campus.",
    "There is a bomb inside the school building. Evacuate now.",
    "I hate everyone at this school and I will make them pay.",
    "Students and teachers will not survive Monday morning.",
    "The school massacre will begin at first period.",
    "I planted explosives in the gymnasium. School bomb threat.",
    "University campus attack planned for graduation ceremony.",
    "I am going to attack the school with weapons I have collected.",
    "The shooting at our school will be worse than Columbine.",
    "I will kill everyone in my classroom before the day is over.",
    "School threat: armed individual planning attack on campus.",
    "I have been planning this school attack for over a year.",
    # Indirect / coded
    "No one's going to want to come to school after what I do tomorrow.",
    "I'd keep your kids home on Thursday if I were you.",
    "The people at Westfield Academy are in for a very bad day.",
    "Something big is going to happen in the cafeteria during lunch.",
    "I've been going to the range every week. The kids at my school are going to find out why.",
    "I already know which periods are the most crowded. I've been watching.",
    "I put something in my locker that my teacher is going to wish I hadn't.",
    "Classes are going to be cancelled soon. I'm going to make sure of that.",
    "The administration has ignored my complaints for the last time.",
    "I've been pushed around at that school for three years. Everyone is going to pay.",
    # Manifesto-style school threats
    "They called me a loser for the last time. I'll show them all on Monday.",
    "Everyone who ever made fun of me is going to understand what real pain feels like.",
    "This school is a prison and I'm going to burn it down one way or another.",
    "The popular kids think they're untouchable. They're wrong.",
    "I've written everything down. People will read it and finally understand.",
    "I've been documenting everything they did to me. Payback is coming.",
    "I don't care about getting caught. I've got nothing left to lose.",
    "My parents tried to take my things but I hid what I need. See you Monday.",
    "I sent letters to three people I trust. If something happens, read them.",
    # Tip / anonymous report style (still a threat)
    "Someone is planning to bring a weapon to Jefferson High this week. Not a drill.",
    "I heard from someone that there's a plan to shoot up the school Friday.",
    "There's a kid at this school who told me exactly what he's going to do. It's serious.",
    "I'm letting you know because I don't want to see anyone get hurt: check the gym lockers.",
    "Someone showed me a note. They mean it. You need to act today.",
]

# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL SAMPLES — added to balance against real ham corpus
# ─────────────────────────────────────────────────────────────────────────────

BOMB_THREAT_2 = [
    "There's no point calling the police. The device goes off either way.",
    "I've hidden it well. You won't find it in time.",
    "The blast radius will reach the neighboring building. Plan accordingly.",
    "I've already armed it. Evacuate or don't — your choice.",
    "The explosion will happen regardless of whether you comply.",
    "Check the supply closet on the third floor before it's too late.",
    "I mailed something to your office. Don't let it sit in the mailroom.",
    "Three packages. Three locations. You can't defuse all of them.",
    "The device was placed two nights ago. It's already inside.",
    "My associate placed the item this morning during the tour.",
    "There's a reason I skipped work today. You should too.",
    "The timing mechanism is already running. You have 45 minutes.",
    "I left something in the bathroom of the 9th floor. Don't use it.",
    "Check your server room. I was there yesterday for a reason.",
    "This building won't be standing by evening. I've made sure of it.",
    "I've given you enough warning. What happens next is on you.",
    "The device I placed is not visible. The scanner won't catch it.",
    "I told you last week I wasn't joking. Now you'll see.",
    "The airport will remember today. Passengers should leave now.",
    "My final gift to this company is already inside the walls.",
    "The power cut tonight isn't an accident. Watch what follows.",
    "You had your chance to listen. The package activates at midnight.",
    "The stadium won't fill up tonight — not if people are smart.",
    "One hour. That's all I'm giving you. The device is live.",
    "Don't bother searching the lobby. It's not in the lobby.",
    "I've done this before. You know I follow through.",
    "The thing about pressure-sensitive devices is they don't care who steps on them.",
    "I've worked in this building for years. I know every blind spot.",
    "My package bypassed security. I know because I watched it happen.",
    "The countdown started at 6 AM. Do the math.",
]

VIOLENCE_2 = [
    "I've already planned exactly how it's going to happen.",
    "You think the distance between us protects you. It doesn't.",
    "I've been watching the route you take home every night.",
    "I've invested in the right tools. You'll understand what I mean soon.",
    "My patience has a hard limit and you've found it.",
    "I know your whole family's schedule. Every one of them.",
    "Don't bother with security. It won't help you where you're going.",
    "This isn't a threat. It's a promise. There's a difference.",
    "Everyone who was involved is going to answer for it.",
    "You'll understand what I meant by this email in a few days.",
    "The people who helped you should be watching their backs too.",
    "I've been waiting for the right moment. It's almost here.",
    "You should check your mirrors more often when you drive.",
    "There's nothing you can do to stop what I've already set in motion.",
    "I'm not in this city anymore. But I will be. Soon.",
    "You embarrassed me in front of everyone. That has consequences.",
    "The last person who did this to me deeply regretted it. So will you.",
    "I've left instructions with someone in case something happens to me first.",
    "You don't answer my calls. You'll answer for that in person.",
    "I am going to find you. I've done it before with less.",
    "Running won't help. I have contacts in every city.",
    "I haven't forgotten what you did. I've just been waiting.",
    "You should have taken my calls. That was your last chance.",
    "I'll be seeing you very soon. You won't know when.",
    "The moment you're alone, that's when I'll be there.",
    "There will be consequences and you'll feel every one of them.",
    "I've hired someone to handle this since you won't take me seriously.",
    "You're going to wish you never crossed me.",
    "The next time you see me will be the last time you see anyone.",
    "I've kept every message you sent me. They won't help you.",
]

TERROR_2 = [
    "The faithful are ready to strike the enemies of the faith.",
    "Our network spans twelve cities. Tonight we strike.",
    "The west will pay for its crimes against our people.",
    "Blood will flow through the streets of the capital by Friday.",
    "We have embedded ourselves in the target location. Awaiting orders.",
    "The chemical compound is ready for deployment in a crowded area.",
    "Civilians are not innocent. They are all legitimate targets.",
    "The first wave is a distraction. The second is real.",
    "We have secured the materials needed for mass casualties.",
    "The infrastructure attack will cascade across three systems.",
    "We have rehearsed this operation many times. It will succeed.",
    "Our people are already inside. You cannot stop what is coming.",
    "The target list is finalized. None of them will be warned.",
    "The vehicle is loaded. The driver is committed to the cause.",
    "Phase one is complete. The next message will come from inside.",
    "No warning will be given to the public. That is intentional.",
    "We have acquired the precursors through intermediaries.",
    "The attack is designed to maximize panic, not just casualties.",
    "Several months of surveillance has given us everything we need.",
    "We will not claim responsibility until after the second attack.",
    "God willing, the operation kills hundreds and paralyzes the city.",
    "The hospital has been selected deliberately. Maximum impact.",
    "We have a sympathizer inside the facility. Access is secured.",
    "The manifesto will be released simultaneously with the operation.",
    "By the time the authorities respond, it will already be done.",
    "This is not an isolated act. It is the first of many.",
    "All units confirm go. The operation is live.",
    "The surveillance cameras in sector B were disabled last Tuesday.",
    "Our martyrs have recorded their final messages. They are at peace.",
    "The strike on the water treatment plant will begin at 3 AM.",
]

EXTORTION_2 = [
    "I have enough to destroy your career. Let's talk price.",
    "The files are encrypted and backed up in four locations. Pay or lose them.",
    "You were recorded. The audio is clear. Wire the amount by Thursday.",
    "Your emails from that week are very incriminating. You know which ones.",
    "I've already contacted two journalists. I'll hold them off for a payment.",
    "We have your location history for the past six months. Interesting reading.",
    "Your search history alone would end your career. Pay to keep it private.",
    "I know about the account you think nobody knows about.",
    "The photos from that night don't belong on the internet. Pay to keep them off.",
    "We installed software on your device eight weeks ago. We have everything.",
    "Three days to respond before the information goes to your wife.",
    "Your business partners have not yet seen what I have. They don't have to.",
    "The amount is modest given what you'd lose if this came out.",
    "I am not bluffing. I have already sent a sample to one contact.",
    "You signed documents you shouldn't have. I have copies.",
    "One payment. That's all it takes for this to go away permanently.",
    "Your children don't need to know about this. Neither does anyone else. Pay me.",
    "I've been sitting on this for six months. I'm done waiting.",
    "The clock resets every 24 hours. Each day you ignore this costs more.",
    "I will post everything unless funds are received by end of day.",
    "The access I have to your systems is still live. Pay before I use it.",
    "Consider this a business transaction. I provide silence. You provide money.",
    "We have the login credentials and full transaction history.",
    "I'm reasonable. I only want what's fair given what you stand to lose.",
    "I've been patient but my patience has a financial value. Meet it.",
    "You deleted the messages. We didn't.",
    "Your assistant doesn't know I've been cc'd on your emails for two months.",
    "The offshore account is known to me. It doesn't need to be known to others.",
    "I have screenshots, recordings, and documents. This is not a bluff.",
    "One transfer. Two accounts. No one ever finds out. Your choice.",
]

HARASSMENT_2 = [
    "I know what time you leave for work. I know which exit you use.",
    "You moved. I found you anyway. Just so you know.",
    "I've been parked outside your building for three evenings now.",
    "Your new number isn't private. I have it.",
    "I know the name of your daughter's teacher.",
    "Every time you block me I find another way through.",
    "I've been forwarding your private messages to a list of people.",
    "Your online profiles have been saved. All of them.",
    "I'll keep creating accounts until you respond to me.",
    "I've already told your colleagues what I know about you.",
    "You don't see me but I see you every single day.",
    "I know the gym you go to and what time you arrive.",
    "Your family's social media is very informative. Especially your mother's.",
    "I followed you to the restaurant last Thursday. The risotto looked good.",
    "I've been leaving you signs. You'll start noticing them.",
    "I know which apartment is yours without the buzzer.",
    "Don't call the police. It'll only make things worse for the people you love.",
    "I've been documenting everything. When I'm ready, everyone will see it.",
    "Your friends don't know what I know. That can change.",
    "I'm going to make sure everyone you care about knows who you really are.",
    "I've been watching for months. I know your whole routine.",
    "The only way this ends is if you talk to me.",
    "You can't get a new phone number fast enough.",
    "I know which train you take. Same one, same time, every day.",
    "I found your home through your running app. You should turn that off.",
    "I'll show up wherever you go until you give me a chance to explain.",
    "I have access to more of your life than you realize.",
    "I've been sending anonymous notes. You found some of them.",
    "Your sister's address is very easy to find online.",
    "The video I have of you is very unflattering. Respond to me.",
]

SCHOOL_THREAT_2 = [
    "Everyone in that school is going to remember my name.",
    "I've been planning this for eight months. I'm ready.",
    "The teachers who failed me are going to answer for it.",
    "I know which periods have the most kids in the hallways.",
    "I put a note in my will about what I'm going to do.",
    "The gym class period is when it happens. I've timed it.",
    "I'm not afraid of getting expelled. There won't be a school to expel me from.",
    "I've recruited one other person. We have a plan.",
    "Graduation day is the last day for a lot of people.",
    "I've been keeping a list of names. It's long.",
    "The administration thinks they handled it. They didn't.",
    "I told one person and made them swear not to tell. They might.",
    "I've been researching incidents at other schools. I know what works.",
    "Monday is the last normal day that school will ever have.",
    "I've been storing things in my car that no one knows about.",
    "The security guard has a pattern. I've mapped it.",
    "The janitor's closet on the second floor has been unlocked for two weeks.",
    "I've written a message for after. People will read it and finally understand.",
    "I'm not doing this for attention. I'm doing this because they deserve it.",
    "The library is where I'm starting because it's always crowded at lunch.",
    "I've got nothing left. Might as well take everyone else with me.",
    "I'm not coming back to that school as a student. I'm coming back differently.",
    "They suspended me for the last time. They're going to regret that.",
    "I've already said goodbye to my dog. That should tell you something.",
    "My backpack tomorrow will be heavier than usual.",
    "I want the people who bullied me to see it coming.",
    "I've been nice about this for three years. No more.",
    "My last homework assignment is the list I've been keeping.",
    "I told my mom I loved her this morning. She thought it was sweet.",
    "The school resource officer won't be enough. I've made sure of that.",
]

# ─────────────────────────────────────────────────────────────────────────────
# Assemble dataset
# ─────────────────────────────────────────────────────────────────────────────
def build_dataset():
    data = []
    categories = [
        (SAFE, "safe"),
        (BOMB_THREAT + BOMB_THREAT_2, "bomb_threat"),
        (VIOLENCE + VIOLENCE_2, "violence"),
        (TERROR + TERROR_2, "terror"),
        (EXTORTION + EXTORTION_2, "extortion"),
        (HARASSMENT + HARASSMENT_2, "harassment"),
        (SCHOOL_THREAT + SCHOOL_THREAT_2, "school_threat"),
    ]
    for samples, label in categories:
        for text in samples:
            data.append({"text": text.strip(), "label": label})

    random.seed(42)
    random.shuffle(data)
    return data


if __name__ == "__main__":
    data = build_dataset()
    with open(OUTPUT_PATH, "w") as f:
        json.dump(data, f, indent=2)

    from collections import Counter
    counts = Counter(d["label"] for d in data)
    print(f"Dataset saved → {OUTPUT_PATH}")
    print(f"Total samples: {len(data)}")
    for label, count in sorted(counts.items()):
        print(f"  {label}: {count}")