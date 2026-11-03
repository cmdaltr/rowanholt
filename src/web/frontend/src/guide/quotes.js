// Short lines from Tolkien for the welcome, one picked at random each start
const QUOTES = [
  { text: 'All we have to decide is what to do with the time that is given us.', who: 'Gandalf', where: 'The Fellowship of the Ring' },
  { text: 'Not all those who wander are lost.', who: 'Bilbo', where: 'The Fellowship of the Ring' },
  { text: 'Even the very wise cannot see all ends.', who: 'Gandalf', where: 'The Fellowship of the Ring' },
  { text: 'It\'s a dangerous business, Frodo, going out your door.', who: 'Bilbo', where: 'The Fellowship of the Ring' },
  { text: 'Faithless is he that says farewell when the road darkens.', who: 'Gimli', where: 'The Fellowship of the Ring' },
  { text: 'The road goes ever on and on.', who: 'Bilbo', where: 'The Fellowship of the Ring' },
  { text: 'Do not meddle in the affairs of wizards, for they are subtle and quick to anger.', who: 'Gildor', where: 'The Fellowship of the Ring' },
  { text: 'Oft hope is born when all is forlorn.', who: 'Legolas', where: 'The Return of the King' },
  { text: 'Many that live deserve death. And some that die deserve life. Can you give it to them?', who: 'Gandalf', where: 'The Fellowship of the Ring' },
  { text: 'So do all who live to see such times. But that is not for them to decide.', who: 'Gandalf', where: 'The Fellowship of the Ring' },
];

export const randomQuote = () => QUOTES[Math.floor(Math.random() * QUOTES.length)];

export default QUOTES;
